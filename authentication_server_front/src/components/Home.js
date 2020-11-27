import React, { Component } from "react";
import { Button, Form, Card } from 'react-bootstrap';
import { register } from "./Functions";

class Home extends Component {

   state = {
      csr:'',
   }

   continue = e => {
      e.preventDefault();
      const {csr} = this.state;

      const data = {
         csr: csr,
     };

     //register({data});
      register({data}).then(res => {
         console.log(res);
         if (res) {
            res.blob().then(blob => {
					let url = window.URL.createObjectURL(blob);
					let a = document.createElement('a');
					a.href = url;
					a.download = 'certificate.csr';
					a.click();
				});
         }
         else {
            console.log('2:Error');
         }
      })
   }

   onChangeHandler=event=>{
      this.setState({
        csr: event.target.files[0],
        loaded: 0,
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
                     <Form.Label>CSR</Form.Label>
                     <Form.Control type="file" name="file" onChange={this.onChangeHandler} required/>
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