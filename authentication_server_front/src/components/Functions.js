export const register = newUser => {


    const data = new FormData()
   data.append('file', newUser.data.csr)

    console.log("register");
 
    return fetch('http://localhost:8081/api/register/', {
       method: 'POST',
       headers: {
         'Access-Control-Allow-Origin': '*',
      },
      body:data,
    })
    //.then((response) => response.json())
    .then(response => {
       return response;
    })
    .catch(err => {
       console.log(err)
    })
 }
 