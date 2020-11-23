import React, { Component } from "react";
import { Button, Form, Card } from 'react-bootstrap';
import { register } from "./Functions";

class Home extends Component {

   state = {
      key:'',
   }

   handleChange = input => e => {
      this.setState({
         [input]: e.target.value
      });
   }

   continue = e => {
      e.preventDefault();
      const {key} = this.state;

      const data = {
         key: key,
     };

      register({data}).then(res => {
         if (res) {
            //let statusCode = res.statusCode;
            console.log(res);
            /*if(statusCode === 'S2000'){
               console.log(res.authToken);
               //localStorage.setItem('usertoken', res.authToken);
               setUserToken(res.authToken);
               this.setState({validInput: true});
               window.location.href = '/home';
            }
            else {
               this.setState({validInput: false, invalidMsg: res.error});
            }*/
         }
         else {
            console.log('Error');
         }
      })
   }


   render() {
      
      return (
         <Card data-testid="login-form">
            <Form onSubmit = {e => this.continue(e)}>
               <Card.Body>
                  <Card.Title className='text-center'>
                     Register
                  </Card.Title>
                  <Form.Group >
                     <Form.Label>Public Key</Form.Label>
                     <Form.Control type="text"  value = {this.state.key} onChange = {this.handleChange('key')} required/>
                  </Form.Group>
                  <br />
                  <Button variant="success" type="submit" block>
                     Continue
                  </Button>
               </Card.Body>
            </Form>
         </Card>
      );
   }
}

export default Home;