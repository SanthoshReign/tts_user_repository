from enum import Enum

class UserRoles(str, Enum):
    employee="employee"
    admin="admin"
    superadmin="superadmin"

class Branches(str, Enum):
    chennai="chennai"
    hyderabad="hyderabad"
    bangalore="bangalore"