export const register = newUser => {

    let data = {
        key: newUser.key,
    }

    console.log("register");
 
    return fetch('localhost:3000/api/register/', {
       method: 'POST',
       headers: {},
       body: JSON.stringify(data)
    })
    .then((response) => response.json())
    .then(response => {
       return response;
    })
    .catch(err => {
       console.log(err)
    })
 }
 