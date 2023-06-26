//! An implementation of [`Display`] for [`Object`]

use core::fmt::{Display, Formatter, Result};

use super::Object;

impl Display for Object
{
	fn fmt(&self, f: &mut Formatter<'_>) -> Result
	{
		match self
		{
			Self::AssignedDepartment => "the department they were assigned to",
			Self::Contact => "contacts",
			Self::CreatedExpenses => "expenses created by themselves",
			Self::CreatedTimesheet => "timesheets created by themselves",
			Self::Department => "departments",
			Self::Employee => "employees",
			Self::EmployeeInDepartment => "employees in their department",
			Self::Expenses => "expenses",
			Self::Job => "jobs",
			Self::JobInDepartment => "jobs in their department",
			Self::Location => "locations",
			Self::Organization => "organization",
			Self::Role => "roles",
			Self::Timesheet => "timesheet",
			Self::User => "users",
			Self::UserInDepartment => "users in their department",
		}
		.fmt(f)
	}
}
