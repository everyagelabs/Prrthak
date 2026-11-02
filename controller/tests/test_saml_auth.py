"""Real RSA/SHA-256 SAML validation against a private in-memory IdP fixture."""
import base64
from datetime import timedelta
import importlib.util
import json
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
import zlib

from controller.auth import AuthDenied, SESSION_COOKIE, initialize
from controller.saml_auth import (CONFIG_ID, MAX_METADATA_BYTES, MAX_RESPONSE_BYTES,
                                  NS, SAMLAuth, SAMLConfig, STATE_COOKIE,
                                  authority_fingerprint, config_from_store, public_user)
from controller.store import Store, digest, now, parse_time, stamp

HAS_SAML = all(importlib.util.find_spec(name) for name in ("onelogin", "xmlsec", "lxml"))
if HAS_SAML:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from lxml import etree
    from onelogin.saml2.utils import OneLogin_Saml2_Utils

ORIGIN = "https://prthak.example.internal:8443"
ENTITY = "https://prthak.example.internal/metadata"
IDP = "https://idp.example.internal/tenant"
SSO = "https://idp.example.internal/saml/login"
SUBJECT = "immutable-directory-person-id"


def fixture_key(*, bits=2048, starts=None, ends=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Private SAML unit fixture")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(starts or now()-timedelta(days=1))
            .not_valid_after(ends or now()+timedelta(days=30)).sign(key, hashes.SHA256()))
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()), cert.public_bytes(serialization.Encoding.PEM)


def fixture_metadata(cert, *, entity=IDP, sso=SSO, use="signing", request_signed=False):
    body = "".join(cert.decode().splitlines()[1:-1])
    return f'''<md:EntityDescriptor xmlns:md="{NS['md']}" xmlns:ds="{NS['ds']}" entityID="{entity}">
      <md:IDPSSODescriptor protocolSupportEnumeration="{NS['samlp']}" WantAuthnRequestsSigned="{'true' if request_signed else 'false'}">
        <md:KeyDescriptor use="{use}"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{body}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{sso}"/>
      </md:IDPSSODescriptor></md:EntityDescriptor>'''


def response_xml(request_id, key, cert, *, subject=SUBJECT, audience=ENTITY, issuer=IDP,
                 destination=ORIGIN+"/api/v1/auth/saml/callback", recipient=None,
                 response_id=None, assertion_id=None, assertion_end=None,
                 starts=None, issued=None, session_end=None, response_request=None,
                 subject_request=None, sign_assertion=True, sign_response=True,
                 mutate=None, weak=False):
    """Public helper reused by the real HTTPS callback integration fixture."""
    tag = lambda name: "{"+NS[name.split(":")[0]]+"}"+name.split(":")[1]
    def add(parent, name, text=None, **attrs):
        result = etree.SubElement(parent, tag(name), **attrs)
        result.text = text
        return result
    at = now()
    end = assertion_end or at+timedelta(minutes=5)
    root = etree.Element(tag("samlp:Response"), nsmap={"samlp":NS['samlp'], "saml":NS['saml']},
                         ID=response_id or "_response_"+secrets.token_hex(12), Version="2.0", IssueInstant=stamp(issued or at),
                         Destination=destination, InResponseTo=response_request or request_id)
    add(root, "saml:Issuer", issuer)
    add(add(root, "samlp:Status"), "samlp:StatusCode", Value="urn:oasis:names:tc:SAML:2.0:status:Success")
    assertion = add(root, "saml:Assertion", ID=assertion_id or "_assertion_"+secrets.token_hex(12), Version="2.0", IssueInstant=stamp(issued or at))
    add(assertion, "saml:Issuer", issuer)
    node = add(assertion, "saml:Subject")
    add(node, "saml:NameID", subject, Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
    confirmation = add(node, "saml:SubjectConfirmation", Method="urn:oasis:names:tc:SAML:2.0:cm:bearer")
    add(confirmation, "saml:SubjectConfirmationData", Recipient=recipient or destination,
        InResponseTo=subject_request or request_id, NotOnOrAfter=stamp(end))
    conditions = add(assertion, "saml:Conditions", NotBefore=stamp(starts or at-timedelta(minutes=1)), NotOnOrAfter=stamp(end))
    add(add(conditions, "saml:AudienceRestriction"), "saml:Audience", audience)
    authn = add(assertion, "saml:AuthnStatement", AuthnInstant=stamp(at), SessionIndex="_fixture_session",
                SessionNotOnOrAfter=stamp(session_end or at+timedelta(hours=1)))
    add(add(authn, "saml:AuthnContext"), "saml:AuthnContextClassRef", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
    # Untrusted directory role/email claims must never grant privileges.
    attributes = add(assertion, "saml:AttributeStatement")
    add(add(attributes, "saml:Attribute", Name="role"), "saml:AttributeValue", "super_admin")
    add(add(attributes, "saml:Attribute", Name="email"), "saml:AttributeValue", "administrator@example.internal")
    if mutate:
        mutate(root, assertion)
    sig = "http://www.w3.org/2000/09/xmldsig#rsa-sha1" if weak else "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    dg = "http://www.w3.org/2000/09/xmldsig#sha1" if weak else "http://www.w3.org/2001/04/xmlenc#sha256"
    if sign_assertion:
        signed = OneLogin_Saml2_Utils.add_sign(etree.tostring(assertion), key, cert, sign_algorithm=sig, digest_algorithm=dg)
        root.replace(assertion, etree.fromstring(signed))
    if sign_response:
        return OneLogin_Saml2_Utils.add_sign(etree.tostring(root), key, cert, sign_algorithm=sig, digest_algorithm=dg)
    return etree.tostring(root)


@unittest.skipUnless(HAS_SAML, "Install controller/requirements.txt for real SAML signature tests")
class SAMLAuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key, cls.cert = fixture_key()
        cls.other_key, cls.other_cert = fixture_key()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.value = {"enabled":True,"sp_entity_id":ENTITY,"origin":ORIGIN,
                      "idp_metadata_xml":fixture_metadata(self.cert),"display_name":"Organisation SSO"}
        self.config = SAMLConfig.from_value(self.value)
        with self.store.meta() as db:
            initialize(db)
            self.store._put(db,"maintenance_settings", {"id":CONFIG_ID,"config":self.value})
        self.auth = SAMLAuth(self.store,self.config)
        self.user = self.auth.user({"subject":SUBJECT,"role":"read_only","display_name":"Read Only fixture"})
        with self.store.meta() as db:self.store._put(db,"auth_users",self.user)

    def begin(self, auth=None):
        auth = auth or self.auth
        login = auth.begin_login({"Host":urlsplit(ORIGIN).netloc})
        params = parse_qs(urlsplit(login['location']).query)
        xml = zlib.decompress(base64.b64decode(params['SAMLRequest'][0]),-15)
        request = etree.fromstring(xml)
        binding = login['cookies'][0].split(';',1)[0]
        self.assertIn('SameSite=None',login['cookies'][0])
        self.assertIn('Secure',login['cookies'][0]);self.assertIn('HttpOnly',login['cookies'][0])
        self.assertEqual(request.get('AssertionConsumerServiceURL'),self.config.acs_url)
        return {"RelayState":params['RelayState'][0]}, {"Cookie":binding,"Host":urlsplit(ORIGIN).netloc}, request.get('ID')

    def payload(self, *, auth=None, key=None, cert=None, **options):
        form, headers, request = self.begin(auth)
        xml = response_xml(request,key or self.key,cert or self.cert,**options)
        form['SAMLResponse'] = base64.b64encode(xml).decode()
        return form,headers

    def principal(self):
        result=self.auth.callback(*self.payload())
        cookie=next(c.split(';',1)[0] for c in result['cookies'] if c.startswith(SESSION_COOKIE+'='))
        return result,{'Cookie':cookie}

    def reject(self, **options):
        with self.assertRaises(AuthDenied):self.auth.callback(*self.payload(**options))

    def test_actual_signed_login_keeps_application_role_and_stable_subject(self):
        result,headers=self.principal();person=result['principal']
        self.assertEqual(person['role'],'read_only')
        self.assertEqual(person['auth_provider'],'saml')
        self.assertEqual(person['actor'],'saml:'+self.user['id'])
        self.assertEqual(person['user']['subject'],SUBJECT)
        self.assertEqual(person['user']['email'],'')
        session=next(c for c in result['cookies'] if c.startswith(SESSION_COOKIE+'='))
        self.assertIn('SameSite=Lax',session);self.assertNotIn('SameSite=None',session)
        self.assertEqual(self.auth.authenticate(headers)['user']['id'],self.user['id'])

    def test_all_three_roles_come_only_from_approved_application_record(self):
        for role in ('read_only','admin','super_admin'):
            with self.subTest(role=role):
                with self.store.meta() as db:
                    self.user['role']=role;self.store._put(db,'auth_users',self.user)
                self.assertEqual(self.principal()[0]['principal']['role'],role)

    def test_identity_cannot_create_accounts_or_use_an_email_claim_as_subject(self):
        self.reject(subject='unprovisioned-directory-id')
        self.assertEqual(len(self.store.all('auth_users')),1)

    def test_disabled_or_role_changed_users_apply_on_every_request(self):
        result,headers=self.principal()
        with self.store.meta() as db:
            self.user['role']='admin';self.store._put(db,'auth_users',self.user)
        self.assertEqual(self.auth.authenticate(headers)['role'],'admin')
        with self.store.meta() as db:
            self.user['enabled']=False;self.store._put(db,'auth_users',self.user)
        self.assertIsNone(self.auth.authenticate(headers))
        self.reject()

    def test_current_config_is_checked_again_and_sessions_do_not_survive_cert_change(self):
        result,headers=self.principal()
        changed={**self.value,'idp_metadata_xml':fixture_metadata(self.other_cert)}
        with self.store.meta() as db:self.store._put(db,'maintenance_settings',{'id':CONFIG_ID,'config':changed})
        with self.assertRaises(AuthDenied):self.auth.authenticate(headers)
        self.assertIsNone(SAMLAuth(self.store,SAMLConfig.from_value(changed)).authenticate(headers))

    def epoch_record(self, epoch=None, value=None):
        value=value or self.value;config=SAMLConfig.from_value(value)
        epoch=epoch or secrets.token_hex(32)
        return {'id':CONFIG_ID,'config':value,'config_digest':digest(value),'epoch':epoch,
                'configuration_fingerprint':config.fingerprint,'realm_id':config.realm_id,
                'fingerprint':digest({'configuration_fingerprint':config.fingerprint,'epoch':epoch})}

    def test_fresh_epoch_retires_existing_cookie_and_pending_state_for_same_settings(self):
        first=self.epoch_record()
        with self.store.meta() as db:self.store._put(db,'maintenance_settings',first)
        self.auth=SAMLAuth(self.store,self.config)
        result,headers=self.principal();form,pending=self.payload()
        self.assertEqual(self.auth.fingerprint,first['fingerprint'])
        with self.store.meta() as db:self.store._put(db,'maintenance_settings',self.epoch_record())
        with self.assertRaises(AuthDenied):self.auth.authenticate(headers)
        replacement=SAMLAuth(self.store,self.config)
        self.assertIsNone(replacement.authenticate(headers))
        with self.assertRaises(AuthDenied):replacement.callback(form,pending)
        self.assertEqual(replacement.callback(*self.payload(auth=replacement))['principal']['role'],'read_only')

    def test_malformed_epoch_cannot_downgrade_to_legacy_semantic_authority(self):
        record=self.epoch_record()
        for update in ({'epoch':'invalid'},{'fingerprint':'0'*64},{'configuration_fingerprint':'0'*64}):
            with self.subTest(update=update),self.assertRaises(AuthDenied):authority_fingerprint(self.config,{**record,**update})

    def test_disabled_quarantine_instance_can_be_constructed_for_a_bad_epoch(self):
        record={**self.epoch_record(),'epoch':'corrupt'}
        with self.store.meta() as db:self.store._put(db,'maintenance_settings',record)
        disabled=SAMLAuth(self.store,SAMLConfig())
        self.assertFalse(disabled.enabled)
        self.assertIsNone(disabled.authenticate({}))

    def test_local_and_oidc_cookie_sessions_are_not_saml_sessions(self):
        for provider in ('local','entra',None):
            raw=secrets.token_urlsafe(32)
            import hashlib
            with self.store.meta() as db:self.store._put(db,'auth_sessions',{'id':hashlib.sha256(raw.encode()).hexdigest(),'provider':provider})
            self.assertIsNone(SAMLAuth(self.store,SAMLConfig()).authenticate({'Cookie':SESSION_COOKIE+'='+raw}))

    def test_real_signatures_reject_unsigned_and_untrusted_signers(self):
        self.reject(sign_response=False);self.reject(sign_assertion=False)
        self.reject(sign_response=False,sign_assertion=False)
        self.reject(key=self.other_key,cert=self.other_cert)

    def test_authenticated_xml_is_not_changed_after_verification(self):
        form,headers=self.payload()
        raw=base64.b64decode(form['SAMLResponse']).replace(SUBJECT.encode(),b'attacker-directory-subject')
        form['SAMLResponse']=base64.b64encode(raw).decode()
        with self.assertRaises(AuthDenied):self.auth.callback(form,headers)

    def test_weak_signature_or_digest_is_rejected(self):
        self.reject(weak=True)

    def test_exact_destination_recipient_and_audience_are_required(self):
        self.reject(destination=self.config.acs_url+'/outside')
        self.reject(recipient='https://attacker.example/'+self.config.acs_url)
        self.reject(audience=ENTITY+'/other')
        self.reject(issuer=IDP+'/other')

    def test_both_outer_and_signed_subject_in_response_to_are_required(self):
        self.reject(response_request='_another_request')
        self.reject(subject_request='_another_request')
        def strip(root,assertion):
            root.attrib.pop('InResponseTo')
        self.reject(mutate=strip)
        def strip_subject(root,assertion):
            assertion.xpath('./saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData',namespaces=NS)[0].attrib.pop('InResponseTo')
        self.reject(mutate=strip_subject)

    def test_missing_or_suffix_bindings_are_rejected_even_with_valid_signatures(self):
        def strip(root,assertion):root.attrib.pop('Destination')
        self.reject(mutate=strip)
        def strip_recipient(root,assertion):assertion.xpath('.//saml:SubjectConfirmationData',namespaces=NS)[0].attrib.pop('Recipient')
        self.reject(mutate=strip_recipient)
        self.reject(recipient=self.config.acs_url+'/unexpected')

    def test_missing_empty_or_ambiguous_audiences_do_not_grant_access(self):
        def missing(root,assertion):
            conditions=assertion.find('{'+NS['saml']+'}Conditions');conditions.remove(conditions[0])
        self.reject(mutate=missing)
        def extra(root,assertion):
            conditions=assertion.find('{'+NS['saml']+'}Conditions')
            extra=etree.SubElement(conditions,'{'+NS['saml']+'}AudienceRestriction')
            etree.SubElement(extra,'{'+NS['saml']+'}Audience').text='urn:not-this-app'
        self.reject(mutate=extra)

    def test_timestamps_expiry_future_issue_and_unbounded_assertions_are_rejected(self):
        self.reject(assertion_end=now()-timedelta(seconds=1))
        self.reject(starts=now()+timedelta(minutes=1))
        self.reject(issued=now()+timedelta(minutes=1))
        self.reject(issued=now()-timedelta(minutes=16))
        self.reject(assertion_end=now()+timedelta(hours=3))
        self.reject(session_end=now()-timedelta(seconds=1))
        def strip(root,assertion):assertion.find('{'+NS['saml']+'}Conditions').attrib.pop('NotOnOrAfter')
        self.reject(mutate=strip)

    def test_normal_entra_saml_assertion_lifetime_and_short_session_expiry(self):
        result=self.auth.callback(*self.payload(assertion_end=now()+timedelta(minutes=70),session_end=now()+timedelta(minutes=2)))
        with self.store.read_meta() as db:
            session=self.store._get(db,'auth_sessions',result['principal']['_session_id'])
        self.assertLess(parse_time(session['expires_at']),now()+timedelta(minutes=3))

    def test_nonpersistent_or_wrong_qualified_subject_is_rejected(self):
        def wrong(root,assertion):assertion.xpath('.//saml:NameID',namespaces=NS)[0].set('Format','urn:oasis:names:tc:SAML:2.0:nameid-format:transient')
        self.reject(mutate=wrong)
        def wrong_qualifier(root,assertion):assertion.xpath('.//saml:NameID',namespaces=NS)[0].set('NameQualifier','urn:other-idp')
        self.reject(mutate=wrong_qualifier)

    def test_multiple_assertions_signature_wrapping_and_duplicate_ids_are_rejected(self):
        def multiple(root,assertion):
            import copy
            root.append(copy.deepcopy(assertion))
        self.reject(mutate=multiple)
        def duplicate(root,assertion):assertion.set('ID',root.get('ID'))
        self.reject(mutate=duplicate)

    def test_callback_needs_browser_cookie_matching_the_pending_request(self):
        form,headers=self.payload()
        with self.assertRaises(AuthDenied):self.auth.callback(form,{})
        with self.assertRaises(AuthDenied):self.auth.callback(form,{'Cookie':STATE_COOKIE+'='+secrets.token_urlsafe(32)})
        self.auth.callback(form,headers)
        with self.assertRaises(AuthDenied):self.auth.callback(form,headers)

    def test_duplicate_callback_parameters_and_duplicate_binding_cookie_fail(self):
        form,headers=self.payload()
        with self.assertRaises(AuthDenied):self.auth.callback({**form,'RelayState':[form['RelayState'],form['RelayState']]},headers)
        with self.assertRaises(AuthDenied):self.auth.callback(form,{'Cookie':headers['Cookie']+'; '+headers['Cookie']})
        self.assertEqual(self.auth.callback({k:[v] for k,v in form.items()},headers)['principal']['role'],'read_only')

    def test_unsolicited_and_expired_states_fail_even_for_valid_signatures(self):
        form,headers=self.payload()
        with self.assertRaises(AuthDenied):self.auth.callback({**form,'RelayState':secrets.token_urlsafe(32)},headers)
        with self.store.meta() as db:
            state=next(s for s in self.store._all(db,'auth_states') if s.get('purpose')=='saml_login')
            state['expires_at']=stamp(now()-timedelta(seconds=1));self.store._put(db,'auth_states',state)
        with self.assertRaises(AuthDenied):self.auth.callback(form,headers)

    def test_assertion_ids_cannot_be_reused_with_another_valid_request(self):
        assertion='_unique_assertion';response='_unique_response'
        self.auth.callback(*self.payload(assertion_id=assertion,response_id=response))
        self.reject(assertion_id=assertion)
        self.reject(response_id=response)

    def test_malformed_base64_xml_dtd_and_oversized_responses_fail_closed(self):
        for raw in ('@not-base64',base64.b64encode(b'<broken').decode(),base64.b64encode(b'<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]><foo>&x;</foo>').decode(),'A'*(MAX_RESPONSE_BYTES*2+1)):
            with self.subTest(kind=raw[:20]):
                form,headers=self.payload();form['SAMLResponse']=raw
                with self.assertRaises(AuthDenied):self.auth.callback(form,headers)

    def test_invalid_response_consumes_state_and_never_echoes_assertion_xml(self):
        form,headers=self.payload();good=form['SAMLResponse'];form['SAMLResponse']='@invalid-secret-assertion'
        with self.assertRaises(AuthDenied) as error:self.auth.callback(form,headers)
        self.assertNotIn('invalid-secret-assertion',str(error.exception))
        form['SAMLResponse']=good
        with self.assertRaises(AuthDenied):self.auth.callback(form,headers)

    def test_canonical_host_redirect_and_callback_host_check(self):
        redirect=self.auth.begin_login({'Host':'other.example'})
        self.assertEqual(redirect,{'location':ORIGIN+'/api/v1/auth/saml/login','cookies':[]})
        form,headers=self.payload()
        with self.assertRaises(AuthDenied):self.auth.callback(form,{**headers,'Host':'other.example'})

    def test_generated_sp_metadata_has_exact_bindings_and_no_private_material(self):
        metadata=self.auth.metadata()
        self.assertIn(ENTITY,metadata);self.assertIn(self.config.acs_url,metadata)
        self.assertIn('WantAssertionsSigned="true"',metadata)
        self.assertNotIn('PRIVATE KEY',metadata);self.assertNotIn(SSO,metadata)
        status=json.dumps(self.auth.status())
        self.assertNotIn('PRIVATE KEY',status);self.assertNotIn('idp_metadata_xml',status)
        self.assertEqual(config_from_store(self.store).fingerprint,self.config.fingerprint)

    def test_missing_provider_config_after_initialization_fails_closed(self):
        form,headers=self.payload()
        with self.store.meta() as db:db.execute('DELETE FROM maintenance_settings WHERE id=?',(CONFIG_ID,))
        with self.assertRaises(AuthDenied):self.auth.callback(form,headers)

    def test_configuration_validates_https_single_idp_and_trusted_signing_certificates(self):
        invalid=[{'origin':'http://prthak.example'},{'origin':ORIGIN+'/path'},{'origin':'https://u:p@prthak.example'},
                 {'idp_metadata_xml':fixture_metadata(self.cert,sso='http://idp.example/saml')},
                 {'idp_metadata_xml':fixture_metadata(self.cert,use='encryption')},
                 {'idp_metadata_xml':fixture_metadata(self.cert,request_signed=True)},
                 {'idp_metadata_xml':'<broken'},{'idp_metadata_xml':'x'*(MAX_METADATA_BYTES+1)},
                 {'idp_metadata_xml':'<!DOCTYPE test><test/>'},{'enabled':'yes'},
                 {'sp_entity_id':''},{'unexpected':True}]
        for change in invalid:
            with self.subTest(change=list(change)):
                with self.assertRaises(ValueError):SAMLConfig.from_value({**self.value,**change})
        container='<md:EntitiesDescriptor xmlns:md="'+NS['md']+'">'+fixture_metadata(self.cert)*2+'</md:EntitiesDescriptor>'
        with self.assertRaises(ValueError):SAMLConfig.from_value({**self.value,'idp_metadata_xml':container})

    def test_expired_and_weak_metadata_certificates_fail_configuration(self):
        for options in ({'ends':now()-timedelta(hours=1),'starts':now()-timedelta(days=3)},{'bits':1024}):
            key,cert=fixture_key(**options)
            with self.assertRaises(ValueError):SAMLConfig.from_value({**self.value,'idp_metadata_xml':fixture_metadata(cert)})

    def test_rollover_metadata_can_pin_next_key_without_using_it_before_activation(self):
        future_key,future_cert=fixture_key(starts=now()+timedelta(days=2),ends=now()+timedelta(days=60))
        current=etree.fromstring(fixture_metadata(self.cert).encode())
        next_key=etree.fromstring(fixture_metadata(future_cert).encode()).xpath('.//md:KeyDescriptor',namespaces=NS)[0]
        current.xpath('./md:IDPSSODescriptor',namespaces=NS)[0].insert(1,next_key)
        value={**self.value,'idp_metadata_xml':etree.tostring(current).decode()}
        config=SAMLConfig.from_value(value)
        self.assertEqual(len(config.signing_certificates),2)
        self.assertEqual(len(config.settings()['idp']['x509certMulti']['signing']),1)
        with patch('controller.saml_auth.now',return_value=now()+timedelta(days=31)):
            self.assertEqual(config.fingerprint,SAMLConfig.from_value(value).fingerprint)
            active=config.settings()['idp']['x509certMulti']['signing']
            self.assertEqual(len(active),1)
            self.assertIn(''.join(future_cert.decode().splitlines()[1:-1]),active)

    def test_untrusted_future_signer_is_rejected_before_its_activation(self):
        key,cert=fixture_key(starts=now()+timedelta(days=1),ends=now()+timedelta(days=10))
        self.reject(key=key,cert=cert)

    def test_subject_provisioning_is_exact_and_cannot_smuggle_identity_or_role(self):
        for change in ({'subject':' '+SUBJECT},{'subject':''},{'subject':'x\nnext'},{'role':'root'},{'enabled':'true'},{'object_id':'fake'}):
            with self.subTest(change=change),self.assertRaises(ValueError):self.auth.user({'subject':SUBJECT,'role':'admin',**change})
        self.assertNotIn('password_hash',public_user(self.user))


if __name__ == '__main__':unittest.main()
