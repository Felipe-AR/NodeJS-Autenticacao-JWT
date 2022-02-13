const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const BearerStrategy = require('passport-http-bearer').Strategy;

const Usuario = require('../usuarios/usuarios-modelo');
const { InvalidArgumentError } = require('../erros');

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const blocklist = require('../../redis/manipula-blocklist');

function verificaUsuario(usuario) {
  if (!usuario) {
    throw new InvalidArgumentError('Não existe um usuário com esse e-mail');
  }
}

async function verificaSenha(senha, senhaHash) {
  const senhaValida = await bcrypt.compare(senha, senhaHash);
  if (!senhaValida) {
    throw new InvalidArgumentError('E-mail ou senha inválidos');
  }
}

async function verificaTokenNaBlackList(token) {
  const tokenNaBlackList = await blacklist.contemToken(token);
  if (tokenNaBlackList) {
    throw new jwt.JsonWebTokenError('Token inválido por logout!');
  }
}

passport.use(
  new LocalStrategy({
    usernameField: 'email',
    passwordField: 'senha',
    session: false
  }, async (email, senha, done) => {
    try {
      const usuario = await Usuario.buscaPorEmail(email);
      verificaUsuario(usuario);
      await verificaSenha(senha, usuario.senhaHash);
      done(null, usuario);
    } catch (erro) {
      done(erro);
    }
  })
)

passport.use(
  new BearerStrategy(
    async (token, done) => {
      try {
        await verificaTokenNaBlackList(token);
        const payload = jwt.verify(token, process.env.CHAVE_JWT);
        const usuario = await Usuario.buscaPorId(payload.id);
        done(null, usuario, { token });
      } catch (erro) {
        done(erro);
      }
    }
  ),
)