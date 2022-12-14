import crypto from 'crypto';
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
    this._script = option.script;
    this._scriptFilePath = option.scriptFilePath;
    this._scriptName = option.scriptName || `${generateHash(option.script)}.js`;
    
  }

  init(context) {
    super.init(context);
    this._context = context;
    this._logger = context.logger;

    context.web.use(BASE_DIR, this._serveScript.bind(this));
    context.web.addHandler('listen', () => {
      const baseUrl = context.web.getHttpBaseUrl();
      const hsed = new HtmlSed();
      const scriptUrl = `${baseUrl}${BASE_DIR}${this._scriptName}`;
      const newSubStr = `$&<script src="${scriptUrl}"></script>`;
      hsed.substitute(/^<\s*body(?:>|\s+.*>)/, newSubStr);
      this.setResponseFilter(hsed);
    });

    this._logger.info(`ScriptInjectrorPlugin loaded. script path: ${BASE_DIR}${this._scriptName}`);
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
    if (req.url != `/${this._scriptName}`) {
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
