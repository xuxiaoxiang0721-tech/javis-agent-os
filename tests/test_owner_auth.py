"""Synthetic authenticator tests in disposable roots; never owner acceptance."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from fido2.cose import ES256
from fido2.webauthn import AttestedCredentialData, AuthenticatorData, AttestationObject, CollectedClientData
from fido2.utils import websafe_encode as enc
import owner_auth as oa

class OwnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='javis-owner-auth-test-')
        self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)
        self.auth = oa.OwnerAuth(self.root, 600)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cid = b'synthetic-credential-only'
        self.credential = AttestedCredentialData.create(b'\0' * 16, self.cid, ES256.from_cryptography_key(self.key.public_key()))
        self.binding = {'action':'confirm','candidate_id':'candidate_test','version_digest':'a'*64,'scope':'cards-master','command_id':'test-1'}

    def response(self, begin, create=False, uv=True, origin=oa.ORIGIN, key=None):
        challenge = begin['options']['publicKey']['challenge']
        client = CollectedClientData.create('webauthn.create' if create else 'webauthn.get', challenge, origin)
        flags = AuthenticatorData.FLAG.UP | (AuthenticatorData.FLAG.UV if uv else 0)
        if create: flags |= AuthenticatorData.FLAG.AT
        auth = AuthenticatorData.create(hashlib.sha256(b'localhost').digest(), flags, 0, bytes(self.credential) if create else b'')
        value = {'id':enc(self.cid),'rawId':enc(self.cid),'type':'public-key','clientExtensionResults':{},'response':{'clientDataJSON':enc(bytes(client))}}
        if create:
            value['response']['attestationObject'] = enc(bytes(AttestationObject.create('none', auth, {})))
        else:
            value['response'].update(authenticatorData=enc(bytes(auth)), signature=enc((key or self.key).sign(bytes(auth)+client.hash,ec.ECDSA(hashes.SHA256()))),userHandle=None)
        return value

    def enroll(self):
        b = self.auth.begin('enroll')
        self.token, self.session = self.auth.complete('enroll', b['request_id'], self.response(b, True))
        self.principal = SimpleNamespace(actor_id=oa.ACTOR,kind='owner',authentication_ref=self.session['auth_ref'])

    def decision(self):
        b = self.auth.begin('decision',self.session,self.binding)
        return b, {'request_id':b['request_id'],'response':self.response(b)}

    def test_enrollment_closed_by_default(self):
        a=oa.OwnerAuth(self.root)
        with self.assertRaises(PermissionError): a.begin('enroll')

    def test_platform_enrollment_and_verified_login(self):
        self.enroll()
        self.assertEqual(oa.verify_principal(self.root,self.principal)['actor_id'],oa.ACTOR)
        b=self.auth.begin('login');token,_=self.auth.complete('login',b['request_id'],self.response(b))
        self.assertEqual(self.auth.session(token)['actor_id'],oa.ACTOR)
        with self.assertRaises(PermissionError):self.auth.begin('enroll')

    def test_no_user_verification_is_rejected(self):
        b=self.auth.begin('enroll')
        with self.assertRaises(ValueError):self.auth.complete('enroll',b['request_id'],self.response(b,True,uv=False))

    def test_wrong_origin_rejected(self):
        b=self.auth.begin('enroll')
        with self.assertRaises(ValueError):self.auth.complete('enroll',b['request_id'],self.response(b,True,origin='http://evil.local'))

    def test_fake_actor_and_plain_boolean_rejected(self):
        self.enroll()
        for principal in [SimpleNamespace(actor_id=oa.ACTOR,kind='owner',authentication_ref='made-up'),SimpleNamespace(actor_id=oa.ACTOR,kind='service',authentication_ref=self.session['auth_ref'])]:
            with self.assertRaises(PermissionError):oa.verify_principal(self.root,principal)
        with self.assertRaises(PermissionError):oa.verify_decision(self.root,True,self.binding)

    def test_signature_and_binding_survive_offline_replay(self):
        self.enroll();b,a=self.decision();proof=oa.verify_decision(self.root,a,self.binding)
        self.auth.sessions.clear()
        self.assertEqual(oa.verify_recorded_decision(self.root,proof['proof_id'],self.binding),proof)
        self.assertFalse((self.root/'raw').exists())

    def test_recorded_proof_verification_is_read_only_including_directory_metadata(self):
        self.enroll();b,a=self.decision();proof=oa.verify_decision(self.root,a,self.binding)
        def snapshot():
            return {str(p.relative_to(self.root)):(p.stat().st_mode,p.stat().st_mtime_ns,p.stat().st_ctime_ns,
                p.read_bytes() if p.is_file() else None) for p in [self.root,*self.root.rglob('*')]}
        before=snapshot()
        self.assertEqual(oa.verify_recorded_decision(self.root,proof['proof_id'],self.binding),proof)
        self.assertEqual(snapshot(),before)

    def test_missing_recorded_proof_does_not_create_owner_directory(self):
        before=list(self.root.iterdir())
        with self.assertRaises((FileNotFoundError,PermissionError,ValueError)):
            oa.verify_recorded_decision(self.root,'owner-proof-'+'a'*48,self.binding)
        self.assertEqual(list(self.root.iterdir()),before)
        self.assertFalse((self.root/'state/owner-auth').exists())

    def test_old_version_and_challenge_replay_rejected(self):
        self.enroll();b,a=self.decision()
        with self.assertRaises(PermissionError):oa.verify_decision(self.root,a,{**self.binding,'version_digest':'b'*64})
        with self.assertRaises(PermissionError):oa.verify_decision(self.root,a,self.binding)

    def test_unsigned_assertion_rejected(self):
        self.enroll();b,a=self.decision();a['response']=self.response(b,key=ec.generate_private_key(ec.SECP256R1()))
        with self.assertRaises(ValueError):oa.verify_decision(self.root,a,self.binding)

    def test_proof_metadata_tampering_cannot_rebind_signature(self):
        self.enroll();b,a=self.decision();proof=oa.verify_decision(self.root,a,self.binding)
        path=self.root/'state/owner-auth/decisions'/(proof['proof_id']+'.json');data=json.loads(path.read_text())
        altered={**self.binding,'action':'reject'};data.update(binding=altered,binding_hash=oa.binding_hash(altered));path.write_text(json.dumps(data))
        with self.assertRaises(ValueError):oa.verify_recorded_decision(self.root,proof['proof_id'],altered)

    def test_expired_session_cannot_confirm(self):
        self.enroll();b,a=self.decision();self.session['expires']=0
        with self.assertRaises(PermissionError):oa.verify_decision(self.root,a,self.binding)

if __name__=='__main__':unittest.main(verbosity=2)
