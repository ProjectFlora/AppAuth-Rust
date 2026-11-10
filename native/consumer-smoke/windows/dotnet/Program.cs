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
    return 0;
}
