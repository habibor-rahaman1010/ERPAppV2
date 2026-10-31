# ERPAppV2 - Modular Monolith with Clean Architecture

## Module structure

Each module lives in `src/Modules/<Name>` and is split into `Domain`, `Application`, `Infrastructure` and `Presentation` projects.
The API host never references module types: at startup it loads every `*.Infrastructure.dll` / `*.Presentation.dll`,
runs their `IServiceInstaller`s and registers their controllers. To add a module, follow the same naming and add a
project reference from `ERPApp.API`. Modules talk to each other only through abstractions in `ERPApp.Shared`.

## Auth module

Endpoints (`/api/auth`): `login`, `refresh`, `logout`, `me`.

- Short-lived JWT access token (`Jwt:AccessTokenMinutes`, default 15) + rotating refresh token (`Jwt:RefreshTokenDays`, default 7).
  Refresh tokens are stored hashed; reusing a rotated token revokes the whole session.
- Account lockout after `Lockout:MaxFailedAttempts` failures for `Lockout:LockoutMinutes` (uses `AspNetUsers.AccessFailedCount` / `LockoutEndDateUtc`).
- Run `src/Modules/Auth/Auth.Infrastructure/Persistence/Scripts/001_CreateRefreshTokens.sql` once on the database.

Protecting an endpoint in any module (menu/action permissions from `tblPagewiseAction`):

```csharp
[HasPermission(12, PermissionActions.Insert)]
public IActionResult Create(...) { ... }
```

Use `ICurrentUser` (from `ERPApp.Shared`) to read the logged-in user's id, role and department.
