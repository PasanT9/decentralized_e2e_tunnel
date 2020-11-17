import React, { Component } from 'react'
import { BrowserRouter as Router, Route } from 'react-router-dom'

import '../node_modules/bootstrap/dist/css/bootstrap.min.css';

import Login from './components/Login'
import Navigationbar from './components/Navigationbar'
import Home from './components/Home'


class App extends Component {

   render() {
      return (
         <Router basename={process.env.PUBLIC_URL}>
            <div className="App">
              <Navigationbar />
              <div className="container">
                  <Route exact path="/login" component={Login} />
                  <Route exact path="/home" component = {Home} />
              </div>
            </div>
         </Router>
      )
   }
}

export default App;