using ProjectFlora.AppAuthRust;

try
{
    await AppAuthWindows.AuthorizeAsync("{");
    return 1;
}
catch (InvalidOperationException)
{
    return 0;
}
