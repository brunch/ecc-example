const ed25519 = require('noble-ed25519');
const secp256k1 = require('noble-secp256k1');
const bls12 = require('noble-bls12-381');
const React = require('preact');

function arrayToHex(array) {
  return Array.from(array)
    .map(c => c.toString(16).padStart(2, "0"))
    .join("");
}

class ECCCalculator extends React.Component {
  constructor() {
    super();
    this.state = {
      privateKey: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      edPub: '207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab6',
      secpPub: '034646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8fff',
      blsPub: '86b50179774296419b7e8375118823ddb06940d9a28ea045ab418c7ecbe6da84d416cb55406eec6393db97ac26e38bd4',
      isLoading: false
    };
  }

  setPrivateKey(value) {
    this.setState({isLoading: true, privateKey: value});
  }

  generateRandomPrivateKey() {
    const array = window.crypto.getRandomValues(new Uint8Array(32));
    this.setPrivateKey(arrayToHex(array));
  }

  onChange(event) {
    const {target: {validity, value}} = event;
    if (validity.valid) this.setPrivateKey(value);
  }

  calculateKeys() {
    const priv = this.state.privateKey;
    const privateKey = priv.replace(/^0x/, '');
    console.log('Getting keys');
    const secpPub = secp256k1.getPublicKey(privateKey, {isCompressed: true});
    console.log('✓ secp');
    // this.setState({secpPub, isLoading: false});
    ed25519.getPublicKey(privateKey).then(edPub => {
      console.log('✓ ed25519');
      const blsPub = arrayToHex(bls12.getPublicKey(privateKey));
      console.log('✓ bls12');
      this.setState({secpPub, edPub, blsPub, isLoading: false});
      if (this.state.message) {
        this.setState({isSigning: true, message: this.state.message});
      }
    })
  }

  onSign(event) {
    this.setState({isSigning: true, message: event.target.value.trim()});
  }

  async calculateSignatures() {
    const msg = this.state.message;
    const priv = this.state.privateKey;
    const privateKey = priv.replace(/^0x/, '');
    const message = new TextEncoder().encode(msg);
    console.log('Signing');
    const ed = await ed25519.sign(msg, privateKey);
    console.log('✓ ed25519', ed);
    const secp = secp256k1.sign(message, privateKey);
    console.log('✓ secp256k1');
    const bls = await bls12.sign(message, privateKey, 1);
    console.log('✓ bls12');
    this.setState({
      edSign: ed,
      secpSign: arrayToHex(secp),
      blsSign: arrayToHex(bls),
      isSigning: false
    });
  }

  componentDidMount() {
    // this.calculateKeys();
  }

  componentDidUpdate() {
    if (this.state.isLoading) {
      setTimeout(() => {this.calculateKeys();}, 50);
    }
    if (this.state.isSigning) {
      setTimeout(() => {this.calculateSignatures();}, 50);
    }
  }

  render() {
    return <div class="ecc-calculator">
      <strong>Private key in hex: </strong>
      <input type="text" maxlength="66" value={this.state.privateKey} pattern="[\daAbBcCdDeEfFxX]{0,66}" onChange={this.onChange.bind(this)} />
      <button className="gen-random-key" onClick={this.generateRandomPrivateKey.bind(this)}>Random</button>

      <h3>Public keys {this.state.isLoading && <div className="lds-hourglass"></div>}</h3>
      <ul>
        <li class="ed"><code>{this.state.edPub}</code></li>
        <li class="secp"><code>{this.state.secpPub}</code></li>
        <li class="bls"><code>{this.state.blsPub}</code></li>
      </ul>

      <div class="ecc-signatures">
        <h3>Signatures {this.state.isSigning && <div className="lds-hourglass"></div>}</h3>
        <strong>Message to sign:</strong>
        <p><textarea onChange={this.onSign.bind(this)}></textarea></p>

        <ul>
          <li class="ed"><code>{this.state.edSign}</code></li>
          <li class="secp"><code>{this.state.secpSign}</code></li>
          <li class="bls"><code>{this.state.blsSign}</code></li>
        </ul>
      </div>
    </div>;
  }
}

document.addEventListener('DOMContentLoaded', function() {
  React.render(<ECCCalculator />, document.querySelector('.ecc-calculator-container'));
});
