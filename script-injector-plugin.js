import crypto from 'crypto';
import path from 'path';
import { SessionProcessorPlugin } from 'sniffkin-session-processor';
import { HtmlSed } from 'html-sed';

const BASE_DIR = '/plugin/sip/';

function generateHash(str) {
  const hash = crypto.createHash('md5');
  return hash.update(str).digest('hex');
}

export class ScriptInjectorPlugin extends SessionProcessorPlugin {
  constructor(option={}) {
    super(option);
    this.pluginName = 'ScriptInjectorPlugin';
    this._scriptUrl = option.scriptUrl;
    this._script = option.script;
    this._scriptFilePath = option.scriptFilePath;
    this._scriptName = option.scriptName;
    this._scriptAsFile = false;
  }

  getScriptUrl(baseUrl) {
    const scriptName = this.getScriptName();
    if (scriptName) {
      return `${baseUrl}${BASE_DIR}${scriptName}`;
    } 
    return '';
  }

  getScriptName() {
    if (this._scriptName) {
      return this._scriptName;
    }
    if (this._script) {
      return `${generateHash(this._script)}.js`;
    }
    if (this._scriptFilePath) {
      return path.basename(this._scriptFilePath);
    }
    return '';
  }

  getScriptTag(baseUrl) {
    const result = [];
    if (this._scriptUrl) {
      result.push(`<script src="${this._scriptUrl}"></script>`);
    }
    if (this._scriptAsFile) {
      const scriptUrl = this.getScriptUrl(baseUrl);
      if (scriptUrl) {
        result.push(`<script src="${scriptUrl}"></script>`);
      }
    } else {
      if (this._script) {
        result.push(`<script>${this._script}</script>`);
      }
    }
    return result.join('\n');
  }

  init(context) {
    super.init(context);
    this._context = context;
    this._logger = context.logger;

    context.web.use(BASE_DIR, this._serveScript.bind(this));
    context.web.addHandler('listen', () => {
      const hsed = new HtmlSed();
      const newSubStr = `$&${this.getScriptTag(context.web.getHttpBaseUrl())}`;
      hsed.substitute(/^<\s*body(?:>|\s+.*>)/, newSubStr);
      this.setResponseFilter(hsed);
    });

    this._logger.info(`ScriptInjectrorPlugin loaded. script path: ${this.getScriptUrl('')}`);
  }

  conditionForRequest(clientRequest) {
    return false;
  }

  conditionForResponse(clientRequest, serverResponse) {
    const ctype = serverResponse.headers['content-type'];
    if (ctype && ctype.startsWith('text/html')) {
      return true;
    }
    return false;
  }

  responseProcessor(clientRequest, proxyResponse) {
    proxyResponse.removeHeader('content-length');
  }

  _serveScript(req, res, next) {
    if (req.url != `/${this.getScriptName()}`) {
      next();
      return;
    }

    if (this._script) {
      res.set('Content-Type', 'text/javascript');
      res.status(200);
      res.send(this._script);
      res.end();
    }
    if (this._scriptFilePath) {
      res.status(200);
      res.sendFile(this._scriptFilePath);
      res.end();
    }
    next();
  }
  
}
