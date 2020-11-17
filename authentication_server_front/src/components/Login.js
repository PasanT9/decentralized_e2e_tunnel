import React, { Component } from 'react'
import GoogleLogin from 'react-google-login'
export class Login extends Component {

  responseGoogle=(response)=>{
    //console.log(response);
    //console.log(response.profileObj);
    window.location.href = '/home';
  }

  render() {
    return (
      <div>
        <GoogleLogin
        clientId="335443951066-ag254oe7ac21iiimoi5kro0lbtvbne8h.apps.googleusercontent.com"
        buttonText="Login"
        onSuccess={this.responseGoogle}
        //onFailure={this.responseGoogle}
        cookiePolicy={'single_host_origin'}
        
        />
      </div>
    )
  }
}

export default Login