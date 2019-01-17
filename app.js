var express     = require('express');
var app         = express();
var path        = require('path');
var mongoose    = require('mongoose');
var passport    = require('passport');
var session     = require('express-session');
var flash       = require ('connect-flash');
var async       = require('async');
var bodyParser  = require('body-parser');
var http        = require('http').Server(app);
var io          = require('socket.io')(http);
var fs          = require('fs');
var multer      = require('multer');
var sharp       = require('sharp');

mongoose.connect('mongodb://' + process.env.MONGO_DB + "@ds155714.mlab.com:55714/hellokwon", {useNewUrlParser: true});

var db = mongoose.connection;
db.once('open', function() {
  console.log('Database is connected');
});
db.on('error', function() {
  console.log('Database ERROR: ', err);
});

var bcrypt = require('bcrypt-nodejs');

var userSchema = mongoose.Schema({
  name: {type: String, required: true, unique: true},
  password: {type: String, required: true},
  admin: {type: Boolean},
  createdAt: {type: Date, default: Date.now}
});
userSchema.pre('save', function(next) {
  if (this.isModified('password')) this.password = bcrypt.hashSync(this.password);
  return next();
});
userSchema.methods.authenticate = function(password) {
  return bcrypt.compareSync(password, this.password);
};
var User = mongoose.model('user', userSchema);

var noticeSchema = mongoose.Schema({
  title: {type: String},
  body: {type: String, required: true},
  author: {type: mongoose.Schema.Types.ObjectId, ref: 'user', required: true},
  createdAt: {type: Date, default: Date.now},
  views: {type: Number, default: 0}
});
var Notice = mongoose.model('notice', noticeSchema);

var imageSchema = mongoose.Schema({
  img: {
    data: {type: Buffer, required: true},
    contentType: {type: String, default: 'image/png'}
  },
  author: {type: mongoose.Schema.Types.ObjectId, ref: 'user', required: true},
  createdAt: {type: Date, default: Date.now},
  views: {type: Number, default: 0}
});
var Image = mongoose.model('image', imageSchema);

var mainSchema = mongoose.Schema({
  title: {type: String, default: '2019 실리콘밸리 체험프로그램'},
  name: {type: String, default: 'main'}
});
var MainInfo = mongoose.model('main', mainSchema);

MainInfo.findOne({name: 'main'}, function(err, main) {
  if (err) return console.log('Main ERROR: ' + err);
  if (!main) {
    MainInfo.create({}, function(err) {
      if (err) return console.log('Main ERROR: ' + err);
    });
  }
});

app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
app.use(flash());
app.use(session({
  secret: 'FourthSiliconValleyCampSecretHashValue%!@^#&)*$_(',
  resave: true,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

var upload = multer({ dest: './uploads', rename: function(fieldname, filename) {
  return filename.replace(/\W+/g, '-').toLowerCase() + Date.now();
}});

passport.serializeUser(function(user, done) {
  done(null, user.id);
});
passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

var LocalStrategy = require('passport-local').Strategy;
passport.use('local-login', new LocalStrategy({
  usernameField: 'name',
  passwordField: 'password',
  passReqToCallback: true
}, function(req, name, password, done) {
  User.findOne({'name': name}, function(err, user) {
    if (err) return done(err);
    if (!user || !user.authenticate(password)) {
      req.flash('name', req.body.name);
      return done(null, false, req.flash('loginError', '이름 또는 비밀번호가 다릅니다'));
    }
    return done(null, user);
  });
}));

io.on('connection', function(socket) {

});

app.get('/', function(req, res) {
  Notice.find({}, function(err) {
    if (err) return res.status(520).render('error', {errorMessage: err});
  }).populate('author').sort('-createdAt').exec(function(err, tNotice) {
    Image.find({}, function(err) {
      if (err) return res.status(520).render('error', {errorMessage: err});
    }).populate('author').sort('-createdAt').exec(function(err, imgs) {
      MainInfo.findOne({name: 'main'}, function(err, main) {
        if (err) return res.status(520).render('error', {errorMessage: err});
        res.render('main', {user: req.user, notice: tNotice[0], notices: tNotice.slice(0, 4), imgs: imgs.slice(0, 4), main: main});
      });
    });
  });
});

app.get('/login', function(req, res) {
  if (req.user) res.render('/loginDone');
  res.render('login/login', {
    name: req.flash('name')[0],
    loginError: req.flash('loginError')[0]
  });
});

app.post('/login', function(req, res, next) {
  req.flash('name');
  if (req.body.name.length === 0 || req.body.password.length === 0) {
    req.flash('name', req.body.name);
    req.flash('loginError', '이름 또는 비밀번호가 다릅니다');
    res.redirect('/login');
  } else next();
}, passport.authenticate('local-login', {
  failureRedirect: '/login',
  failureFlash: true
}), function(req, res, next) {
  if (req.body.remember === 'on') req.session.cookie.maxAge = 7 * 24 * 60 * 60 * 1000; // cookie expires after 7 days
  else req.session.cookie.expires = false;
  res.redirect('/loginDone');
});

app.get('/loginDone', function(req, res) {
  var destination = req.session.returnTo || '/';
  delete req.session.returnTo;
  res.redirect(destination);
});

app.get('/logout', function(req, res) {
  req.logout();
  res.redirect('/');
});

app.get('/users/new', function(req, res) {
  res.render('users/new', {
    formData: req.flash('formData')[0],
    registerError: req.flash('registerError')[0]
  });
});

app.post('/users', function (req, res, next) {
  if (!req.body.user.name) {
    req.flash('registerError', '이름을 입력해주세요');
    req.flash('formData', req.body.user);
    res.redirect('back');
  } else if (!req.body.user.password || !req.body.user.passwordConfirmation) {
    req.flash('registerError', '비밀번호를 입력해주세요');
    req.flash('formData', req.body.user);
    res.redirect('back');
  } else if (req.body.user.password !== req.body.user.passwordConfirmation) {
    req.flash('registerError', '비밀번호가 일치하지 않습니다');
    req.flash('formData', req.body.user);
    res.redirect('back');
  } else next();
}, checkUserRegValidation, function(req, res) {
  User.create(req.body.user, function(err, user) {
    if (err) return res.status(520).render('error', {errorMessage: err});
    res.redirect('/login');
  });
});

app.get('/users', isLoggedin, function(req, res) {
  res.redirect('/users/' + req.user._id);
});

app.post('/users/auth/:to', isLoggedin, function(req, res) {
  if (req.body.user.password !== req.body.user.passwordConfirmation || !req.user.authenticate(req.body.user.password)) {
    req.flash('userError', '비밀번호가 다릅니다');
    res.redirect('back');
  } else res.redirect('/users/' + req.params.to);
});

app.get('/users/delete', isLoggedin, function(req, res) {
  res.redirect('/users/delete/' + req.user._id);
});

app.get('/users/delete/:id', isLoggedin, function(req, res) {
  User.findOne({_id: req.params.id}, function(err, user) {
    if (err) return res.status(520).render('error', {errorMessage: err});
    if (!user) return res.status(400).render('error', {errorMessage: '400 Bad Request'});
    if (req.user.admin !== true && req.user._id.toString() != user._id.toString()) req.status(403).render('error', {errorMessage: '403 Forbidden'});
    res.render('users/delete', {user: user, userError: req.flash('userError')[0], admin: user.admin !== true && req.user.admin === true});
  });
});

app.post('/users/delete/:id', function(req, res, next) {
  if (req.user && req.user.admin === true) return next();
  if (!req.user) return res.status(401).render('error', {errorMessage: '401 Unauthorized'});
  else if (!req.user.authenticate(req.body.user.password)) {
    req.flash('userError', '비밀번호가 다릅니다');
    res.redirect('back');
  } else if (req.user.id != req.params.id) return res.status(403).render('error', {errorMessage: '403 Forbidden'});
  else next();
}, function(req, res) {
  User.findOneAndRemove({_id: req.params.id}, function(err, user) {
    if (err) return res.status(520).render('error', {errorMessage: err});
    if (!user) return res.status(400).render('error', {errorMessage: "400 Bad Request"});
    res.redirect('/');
  });
});

app.get('/users/edit', isLoggedin, function(req, res) {
  res.redirect('/users/edit/' + req.user._id);
});

app.get('/users/edit/:id', isLoggedin, function(req, res) {
  User.findOne({_id: req.params.id}, function(err, user) {
    if (err) return res.status(520).render('error', {errorMessage: err});
    if (!user) return res.status(400).render('error', {errorMessage: '400 Bad Request'});
    if (req.user.admin !== true && req.user._id.toString() != user._id.toString()) req.status(403).render('error', {errorMessage: '403 Forbidden'});
    res.render('users/edit', {user: user, userError: req.flash('userError')[0], admin: user.admin !== true && req.user.admin === true});
  });
});

app.post('/users/edit/:id', function(req, res, next) {
  if (req.user && req.user.admin === true) return next();
  if (!req.user) return res.status(401).render('error', {errorMessage: '401 Unauthorized'});
  else if (!req.user.authenticate(req.body.user.currentPassword)) {
    req.flash('userError', '비밀번호가 다릅니다');
    res.redirect('back');
  } else if (req.body.user.password !== req.body.user.passwordConfirmation) {
    req.flash('userError', '비밀번호가 일치하지 않습니다');
    res.redirect('back');
  } else if (req.user.id != req.params.id) res.status(403).render('error', {errorMessage: '403 Forbidden'});
  else next();
}, function(req, res) {
  var nUser = req.body.user;
  nUser.password = bcrypt.hashSync(nUser.password);
  User.findOneAndUpdate({_id: req.params.id}, nUser, function(err, user) {
    if (err) return res.status(520).render('error', {errorMessage: err});
    if (!user) return res.status(400).render('error', {errorMessage: "400 Bad Request"});
    res.redirect('/users/' + user._id);
  });
});

app.get('/users/:id', function(req, res) {
  User.findOne({_id: req.params.id}, function(err, user) {
    if (err) return res.status(520).render('error', {errorMessage: err});
    if (!user) return res.status(400).render('error', {errorMessage: '400 Bad Request'});
    res.render('users/user', {user: user, own: req.user && (req.user.admin === true || req.user._id == req.params.id)});
  });
});

app.get('/notice', function(req, res) {
  req.session.returnTo = req.originalUrl;
  Notice.find({}, function(err) {
    if (err) return res.status(520).render('error', {errorMessage: err});
  }).populate('author').sort('-createdAt').exec(function(err, notices) {
    if (err) return res.status(520).render('error', {errorMessage: err});
    res.render('notice/posts', {user: req.user, posts: notices, notice: notices[0]});
  });
});

app.post('/notice', function(req, res) {
  if (!req.user) {
    req.session.returnTo = '/notice/new';
    req.session.previousBody = req.body.notice.body;
    res.redirect('/login');
  } else if (req.user.admin !== true) res.render('error', {errorMessage: '403 Forbidden'});
  else {
    var nNotice = req.body.notice;
    nNotice.author = req.user._id;
    Notice.create(nNotice, function(err, notice) {
      if (err) return res.status(520).render('error', {errorMessage: err});
      res.redirect('/notice');
    });
  }
});

app.get('/notice/new', isLoggedin, isAdmin, function(req, res) {
  req.session.returnTo = req.originalUrl;
  var formData = '';
  if (req.session.previousBody) {
    formData = req.session.previousBody;
    delete req.session.previousBody;
  }
  res.render('notice/new', {user: req.user, formData: formData});
});

app.get('/notice/:id', function(req, res) {
  req.session.returnTo = req.originalUrl;
  Notice.findOneAndUpdate({_id: req.params.id}, {$inc: {views: 1}}, function(err) {
    if (err) return res.status(520).render('error', {errorMessage: err});
  });
  Notice.findOne({_id: req.params.id}, function(err) {
    if (err) return res.status(520).render('error', {errorMessage: err});
  }).populate('author').exec(function(err, notice) {
    Notice.findOne({}, function(err) {
      if (err) return res.status(520).render('error', {errorMessage: err});
    }).populate('author').sort('-createdAt').exec(function(err, tNotice) {
      if (err) return res.status(520).render('error', {errorMessage: err});
      else if (!notice) return res.status(400).render('error', {errorMessage: '400 Bad Request\n게시물이 삭제된 것 같습니다.'});
      else res.render('notice/post', {user: req.user, post: notice, notice: tNotice});
    });
  });
});

app.get('/notice/:id/delete', isLoggedin, function(req, res) {
  Notice.findOneAndRemove(req.user.admin === true ? {_id: req.params.id} : {_id: req.params.id, author: req.user._id}, function(err, notice) {
    if (err) return res.status(520).render('error', {errorMessage: err});
    else if (!notice) return res.render('error', {errorMessage: '400 Bad Request'});
    else res.redirect('/notice');
  });
});

app.post('/notice/:id', isLoggedin, function(req, res) {
  Notice.findOneAndUpdate(req.user.admin === true ? {_id: req.params.id} : {_id: req.params.id, author: req.user._id}, req.body.notice, function(err, notice) {
    if (err) return res.status(520).render('error', {errorMessage: err});
    else if (!notice) return res.render('error', {errorMessage: '400 Bad Request'});
    else res.redirect('/notice');
  });
})

app.get('/notice/:id/edit', isLoggedin, function(req, res) {
  Notice.findOne({_id: req.params.id}, function(err, notice) {
    if (err) return res.status(520).render('error', {errorMessage: err});
    else if (notice.author._id.toString() != req.user._id.toString() && req.user.admin !== true) return res.status(403).render('error', {errorMessage: '403 Forbidden'});
    else res.render('notice/edit', {user: req.user, post: notice});
  });
});

app.get('/photo', function(req, res) {
  req.session.returnTo = req.originalUrl;
  Image.find({}, function(err) {
    if (err) return res.status(520).render('error', {errorMessage: err});
  }).populate('author').sort('-createdAt').exec(function(err, images) {
    if (err) return res.status(520).render('error', {errorMessage: err});
    res.render('photo/posts', {user: req.user, imgs: images, notice: null});
  });
});

app.get('/photo/new', isLoggedin, function(req, res) {
  req.session.returnTo = req.originalUrl;
  res.render('photo/new', {user: req.user});
});

app.post('/photo', isLoggedin, upload.single('fileInput'), function(req, res) {
  var newItem = new Image();
  sharp(req.file.path).resize(1024, 1024, { widthoutEnlargement: true, fit: 'inside'}).toFile(req.file.path + 'edited', function(err) {
    if (err) return console.log('IMG ERROR: ', tErr);
    newItem.img.data = fs.readFileSync(req.file.path + 'edited');
    newItem.img.contentType = req.file.mimetype;
    newItem.author = req.user._id;
    newItem.save();
    res.redirect('/photo');
  });
});

app.get('/photo/:id', function(req, res) {
  Image.findOneAndUpdate({_id: req.params.id}, {$inc: {views: 1}}, function(err) {
    if (err) return res.status(520).render('error', {errorMessage: err});
  });
  Image.findOne({_id: req.params.id}, function(err) {
    if (err) return res.status(520).render('error', {errorMessage: err});
  }).populate('author').sort('-createdAt').exec(function(err, img) {
    if (!img) return res.status(400).render('error', {errorMessage: '400 Bad Request'});
    res.render('photo/post', {user: req.user, img: img, notice: null});
  });
});

app.get('/photo/:id/raw', function(req, res) {
  Image.findOne({_id: req.params.id}, function(err, image) {
    if (err) return res.status(520).render('error', {errorMessage: err});
    if (!image) return res.status(400).render('error', {errorMessage: '400 Bad Request'});
    res.header('Content-Type', image.img.contentType).send(image.img.data);
  });
});

app.get('/photo/:id/delete', isLoggedin, function(req, res) {
  Image.findOneAndRemove(req.user.admin === true ? {_id: req.params.id} : {_id: req.params.id, author: req.user._id}, function(err, image) {
    if (err) return res.status(520).render('error', {errorMessage: err});
    else if (!image) return res.render('error', {errorMessage: '400 Bad Request'});
    else res.redirect('/photo');
  });
});

app.post('/change', isLoggedin, isAdmin, function(req, res) {
  MainInfo.findOneAndUpdate({name: 'main'}, req.body.main, function(err, main) {
    if (err) return console.log('Title ERROR: ' + err);
    console.log(main);
  });
  res.redirect('/');
});

http.listen(process.env.PORT || 3000, function() {
  console.log('Server is now ON!');
});

function checkUserRegValidation(req, res, next) {
  var isValid = true;

  async.waterfall([
    function(callback) {
      User.findOne({name: req.body.user.name, _id: {$ne: mongoose.Types.ObjectId(req.params.id)}}, function(err, user) {
        if (user) {
          isValid = false;
          req.flash('registerError', '이미 가입되었습니다');
        }
        callback(null, isValid);
      });
    }], function(err, isValid) {
      if (err) return res.status(520).render('error', {errorMessage: err});
      if (isValid) return next();
      else {
        req.flash('formData', req.body.user);
        res.redirect('back');
      }
    });
};

function isLoggedin(req, res, next) {
  if (!req.user) {
    req.session.returnTo = req.originalUrl;
    res.redirect('/login');
  } else next();
}

function isAdmin(req, res, next) {
  if (!req.user || req.user.admin !== true) res.render('error', {errorMessage: '403 Forbidden'});
  else next();
}

function includes(arr, entity) {
  for (var i = 0; i < arr.length; i++) if (arr[i] === entity) return true;
  return false;
}

app.get('*', function(req, res) {
  res.status(404).render('error', {errorMessage: '404 Not Found'});
});
