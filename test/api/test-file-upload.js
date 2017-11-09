const chai = require('chai');
const chaiHttp = require('chai-http');
const fs = require('fs-extra');
const nock = require('nock');
const path = require('path');

const server = require('../../lib/server.js');
const db = require('../scripts/populate-db.js');
const config = require('../../lib/config/config.js');

const should = chai.should();
chai.use(chaiHttp);

describe('File upload', () => {
  let events;
  let omscoreStub;
  let omsserviceregistryStub;

  beforeEach(async () => {
    db.clear();

    // Populate db
    const res = await db.populateEvents();
    events = res.events;
    
    omsserviceregistryStub = nock(config.registry.url + ':' + config.registry.port)
      .get('/services/omscore-nginx')
      .replyWithFile(200, path.join(__dirname, '..', 'assets', 'oms-serviceregistry-valid.json'));

    omscoreStub = nock('http://omscore-nginx')
      .post('/api/tokens/user')
      .replyWithFile(200, path.join(__dirname, '..', 'assets', 'oms-core-valid.json'));
  });

  after(() => {
    fs.removeSync(config.media_dir);
  });

  it('should create an upload folder if it doesn\'t exist', (done) => {
    fs.removeSync(config.media_dir);

    chai.request(server)
      .post(`/single/${events[0]._id}/upload`)
      .set('X-Auth-Token', 'foobar')
      .attach('head_image', fs.readFileSync('./test/assets/valid_image.png'), 'image.png')
      .end((err) => {
        fs.existsSync(config.media_dir).should.be.true;
        done();
      });
  });

  it('should fail if the uploaded file is not an image (by extension)', (done) => {
    chai.request(server)
      .post(`/single/${events[0]._id}/upload`)
      .set('X-Auth-Token', 'foobar')
      .attach('head_image', fs.readFileSync('./test/assets/invalid_image.txt'), 'image.txt')
      .end((err, res) => {
        res.should.have.status(500);
        res.should.be.json;
        res.should.be.a('object');

        res.body.success.should.be.false;
        res.body.should.have.property('message');

        done();
      });
  });

  it('should fail if the uploaded file is not an image (by content)', (done) => {
    chai.request(server)
      .post(`/single/${events[0]._id}/upload`)
      .set('X-Auth-Token', 'foobar')
      .attach('head_image', fs.readFileSync('./test/assets/invalid_image.jpg'), 'image.jpg')
      .end((err, res) => {
        res.should.have.status(500);
        res.should.be.json;
        res.should.be.a('object');

        res.body.success.should.be.false;
        res.body.should.have.property('message');

        done();
      });
  });

  it('should fail the \'head_image\' field is not specified', (done) => {
    chai.request(server)
      .post(`/single/${events[0]._id}/upload`)
      .set('X-Auth-Token', 'foobar')
      .end((err, res) => {
        res.should.have.status(500);
        res.should.be.json;
        res.should.be.a('object');

        res.body.success.should.be.false;
        res.body.should.have.property('message');

        done();
      });
  });

  it('should upload a file if it\'s valid', (done) => {
    chai.request(server)
      .post(`/single/${events[0]._id}/upload`)
      .set('X-Auth-Token', 'foobar')
      .attach('head_image', fs.readFileSync('./test/assets/valid_image.png'), 'image.png')
      .end((err, res) => {
        res.should.have.status(200);
        res.should.be.json;
        res.should.be.a('object');

        res.body.success.should.be.true;
        res.body.should.have.property('data');

        done();
      });
  });
});
