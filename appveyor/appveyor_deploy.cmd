IF %APPVEYOR_REPO_TAG%==true (
    ECHO Deploying since this is a tag commit
    %PYTHON%\\python.exe -m twine upload dist\* -u aantonitis -p %PYPI_PASS% --skip-existing
)
