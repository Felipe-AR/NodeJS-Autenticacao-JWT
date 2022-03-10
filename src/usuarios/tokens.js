const allowListRefreshToken = require('../../redis/allowlist-refresh-token');
const blocklistAccessToken = require('../../redis/blocklist-access-token');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const moment = require('moment');

const { InvalidArgumentError } = require('../erros');

function criaTokenJWT(id, [tempoQuantidade, tempoUnidade]) {
  const payload = { id };
  const token = jwt.sign(payload, process.env.CHAVE_JWT, { expiresIn: tempoQuantidade + tempoUnidade });
  return token;
}

async function criaTokenOpaco(id, [tempoQuantidade, tempoUnidade], allowlist) {
  const tokenOpaco = crypto.randomBytes(24).toString('hex');
  const dataExpiracao = moment().add(tempoQuantidade, tempoUnidade).unix();
  await allowlist.adiciona(tokenOpaco, id, dataExpiracao);
  return tokenOpaco;
}

async function verificaTokenNaBlockList(token, nome, blocklist) {
  if (!blocklist) return;
  const TokenNaBlockList = await blocklist.contemToken(token);
  if (TokenNaBlockList) {
    throw new jwt.JsonWebTokenError(`${nome} por logout!`);
  }
}

function invalidaTokenJWT(token, blocklist) {
  return blocklist.adiciona(token);
}

async function verificaTokenJWT(token, nome, blocklist) {
  await verificaTokenNaBlockList(token, nome, blocklist);
  const { id } = jwt.verify(token, process.env.CHAVE_JWT);
  return id;
}

async function verificaTokenOpaco(token, nome, allowlist) {
  verificaTokenEnviado(token, nome);
  const id = await allowlist.buscaValor(token);
  verificaTokenValido(id, nome);
  return id;
}

async function invalidaTokenOpaco(token, allowlist) {
  await allowlist.deleta(token);
}

function verificaTokenEnviado(token, nome) {
  if (!token) {
    throw new InvalidArgumentError(`${nome} não enviado!`);
  }
}

function verificaTokenValido(id, nome) {
  if (!id) {
    throw new InvalidArgumentError(`${nome} inválido`);
  }
}

module.exports = {
  access: {
    nome: 'access token',
    lista: blocklistAccessToken,
    expiracao: [15, 'm'],
    cria(id) {
      return criaTokenJWT(id, this.expiracao);
    },
    verifica(token) {
      return verificaTokenJWT(token, this.nome, this.lista);
    },
    invalida(token) {
      return invalidaTokenJWT(token, this.lista);
    }
  },

  refresh: {
    nome: 'refresh token',
    lista: allowListRefreshToken,
    expiracao: [4, 'd'],
    cria(id) {
      return criaTokenOpaco(id, this.expiracao, this.lista);
    },
    verifica(token) {
      return verificaTokenOpaco(token, this.nome, this.lista);
    },
    invalida(token) {
      return invalidaTokenOpaco(token, this.lista);
    }
  },

  verificacaoEmail: {
    nome: 'verify e-mail token',
    expiracao: [5, 'm'],
    cria(id) {
      return criaTokenJWT(id, this.expiracao);
    },
    verifica(token) {
      return verificaTokenJWT(token, this.nome);
    }
  }
}