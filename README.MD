# Reviewer

Reviewer is an application where users can create lists of things as well as a give them a 5 star review to them. 

## Migrations

To create a migration use `migrate create -ext sql -dir migrations -seq <description>`

To execute migrations use `migrate -database sqlite3://./users.db -path ./migrations up`