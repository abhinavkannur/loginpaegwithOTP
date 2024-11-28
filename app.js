const express=require('express');
const mongoose=require('mongoose');
const cookiePareser=require('cookie-parser');
const bodyParser=require('body-parser');
const userauth=require('./router/auth')
const adminauth=require('./router/admin')

const app=express();

//mongodb  connection
mongoose
.connect('mongodb://localhost:27017/adminpanel')
.then(()=>console.log('mongodb connected sucessfully'))
.catch((err)=>console.log('error in mongodb connection ',err));

//middleware

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(bodyParser.urlencoded({extended:true}));
app.use(bodyParser.json());
app.use(cookiePareser());

//Routes

app.use('/',userauth);
app.use('/',adminauth);

//startserver
app.listen(3000,()=>{
  console.log('server started');
})


