using System;
using ProjectFlora.AppAuthRust;

try
{
    await AppAuthWindows.AuthorizeAsync("{");
}
catch (InvalidOperationException)
{
}

try
{
    await AppAuthWindows.RevokeAsync("{");
    return 1;
}
catch (InvalidOperationException)
{
}

try
{
    await AppAuthWindows.RefreshAsync("{");
    return 1;
}
catch (InvalidOperationException)
{
}

try
{
    await AppAuthWindows.EndSessionAsync("{");
    return 1;
}
catch (InvalidOperationException)
{
    return 0;
}
