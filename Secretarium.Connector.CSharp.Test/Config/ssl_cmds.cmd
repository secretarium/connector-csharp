set CD=%~dp0

set /p name="name:"
openssl ecparam -genkey -name prime256v1 -out "%CD%%name%.key"
openssl req -new -nodes -key "%CD%%name%.key" -out "%CD%%name%.csr" -subj "/O=Secretarium/CN=%name%/emailAddress=fakecert@secretarium.org"
openssl req -x509 -nodes -days 3650 -key "%CD%%name%.key" -in "%CD%%name%.csr" -out "%CD%%name%.crt"
openssl pkcs12 -export -out "%CD%%name%.pfx" -inkey "%CD%%name%.key" -in "%CD%%name%.crt" -password pass:%name%
openssl x509 -in "%CD%%name%.crt" -text -noout
openssl verify "%CD%%name%.crt"

pause