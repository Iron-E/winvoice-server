use pretty_assertions::assert_eq;
use winvoice_export::Format;

#[allow(clippy::wildcard_imports)]
use super::*;

#[tokio::test]
#[traced_test]
async fn export() -> DynResult<()>
{
	let TestData { admin, client, pool, .. } = setup("export").await?;

	let contact_ = {
		let (kind, label) = contact_args();
		PgContact::create(&pool, kind, label).await?
	};

	let department = PgDepartment::create(&pool, rand_department_name()).await?;

	let employee = {
		let (d, name_, title) = employee_args(&department);
		PgEmployee::create(&pool, d, name_, title).await?
	};

	let job_client = {
		let (currency, address_, outer) = location_args();
		let loc = PgLocation::create(&pool, currency, address_, outer).await?;
		PgOrganization::create(&pool, loc, company::company()).await?
	};

	let organization = {
		let (currency, address_, outer) = location_args();
		let loc = PgLocation::create(&pool, currency, address_, outer).await?;
		PgOrganization::create(&pool, loc, company::company()).await?
	};

	let job_ = {
		let mut tx = pool.begin().await?;
		let (date_close, date_open, increment, invoice, notes, objectives) = job_args();
		let j = PgJob::create(
			&mut tx,
			job_client.clone(),
			date_close,
			date_open,
			[department.clone()].into_iter().collect(),
			increment,
			invoice,
			notes,
			objectives,
		)
		.await?;

		tx.commit().await?;
		j
	};

	let timesheet = {
		let mut tx = pool.begin().await?;
		let (_, time_begin, time_end, work_notes) = timesheet_args();
		let t = PgTimesheet::create(
			&mut tx,
			employee.clone(),
			iter::repeat_with(expense_args).take(2).collect(),
			job_.clone(),
			time_begin,
			time_end,
			work_notes,
		)
		.await?;

		tx.commit().await?;
		t
	};

	client.login(admin.0.username(), &admin.1).await;
	let rates = ExchangeRates::new().await?;

	{
		let response = client
			.get_builder(routes::EXPORT)
			.json(&request::Export::new(None, Format::Markdown, vec![job_.clone()], organization.clone()))
			.send()
			.await;

		let actual = Response::new(response.status(), response.json::<Export>().await);
		let expected = Response::from(Export::new(
			[(
				format!("{}--{}.{}", job_client.name.replace(' ', "-"), job_.id, Format::Markdown.extension()),
				Format::Markdown.export_job(
					&job_.clone().exchange(job_client.location.currency(), &rates),
					&[contact_.clone()],
					&organization,
					&[timesheet.clone().exchange(job_client.location.currency(), &rates)],
				),
			)]
			.into_iter()
			.collect(),
			Code::Success.into(),
		));

		assert_eq!(actual, expected);
	}

	{
		let response = client
			.get_builder(routes::EXPORT)
			.json(&request::Export::new(
				Currency::Nok.into(),
				Format::Markdown,
				vec![job_.clone()],
				organization.clone(),
			))
			.send()
			.await;

		let actual = Response::new(response.status(), response.json::<Export>().await);
		let expected = Response::from(Export::new(
			[(
				format!("{}--{}.{}", job_client.name.replace(' ', "-"), job_.id, Format::Markdown.extension()),
				Format::Markdown.export_job(
					&job_.clone().exchange(Currency::Nok, &rates),
					&[contact_.clone()],
					&organization,
					&[timesheet.clone().exchange(Currency::Nok, &rates)],
				),
			)]
			.into_iter()
			.collect(),
			Code::Success.into(),
		));

		assert_eq!(actual, expected);
	}

	client.logout().await;

	let users: Vec<_> = [&admin.0].into_iter().cloned().collect();
	let roles: Vec<_> = users.iter().map(|u| u.role().clone()).collect();

	futures::try_join!(PgUser::delete(&pool, users.iter()), PgJob::delete(&pool, [&job_].into_iter()),)?;

	futures::try_join!(
		PgEmployee::delete(&pool, users.iter().filter_map(User::employee).chain([&employee])),
		PgOrganization::delete(&pool, [&organization, &job_client].into_iter()),
		PgRole::delete(&pool, roles.iter()),
	)?;

	futures::try_join!(
		PgContact::delete(&pool, [&contact_].into_iter()),
		PgLocation::delete(&pool, [&organization, &job_client].into_iter().map(|o| &o.location)),
		PgDepartment::delete(
			&pool,
			users.iter().filter_map(User::department).chain([&employee.department, &department])
		),
	)?;

	Ok(())
}
