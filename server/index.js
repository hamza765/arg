import http from 'http';
import express from 'express';
import morgan from 'morgan';
import bodyParser from 'body-parser';
import middleware from './middleware';
import api from './api';

var app = express();
app.server = http.createServer(app);

// configure app
app.use(morgan('dev')); // log requests to the console

// configure body parser
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(express.static('./client'));

// internal middleware
app.use(middleware());

// api router
app.use('/api', api());

app.server.listen(process.env.PORT || 8080);

console.log(`Started on port ${app.server.address().port}`);

export default app;
