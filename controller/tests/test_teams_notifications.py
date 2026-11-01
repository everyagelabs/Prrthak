import json
import unittest
from unittest.mock import Mock,patch
from controller import notifications as n
from controller.tests import test_notifications as fixtures


class TeamsNotificationsTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.NotificationTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)

    def test_teams_workflow_is_reviewed_with_secret_url_hidden(self):
        url='https://prod-01.westeurope.logic.azure.com/workflows/test/triggers/manual/paths/invoke?sig=not-real'
        channel=self.fixture.channel(type='teams',url=url,idempotency_supported=False)
        plan=n.preview(self.fixture.manager,self.fixture.body([channel]),'admin',resolver=self.fixture.resolver)
        self.assertEqual(plan['summary']['channels'][0]['type'],'teams')
        self.assertNotIn('not-real',json.dumps(plan))
        with self.assertRaises(ValueError):
            n.preview(self.fixture.manager,self.fixture.body([self.fixture.channel(type='teams',url='https://logic.azure.com.attacker.test/token')]),'admin',resolver=self.fixture.resolver)

    def test_teams_adaptive_card_uses_bounded_payload_and_tls_transport(self):
        channel={'type':'teams','host':'prod-01.westeurope.logic.azure.com','port':443,'addresses':['8.8.8.8'],
                 'url':'https://prod-01.westeurope.logic.azure.com/workflows/test?sig=not-real'}
        delivery={'id':'delivery-test','attempts':1,'event':{'id':'event-test','severity':'warning','kind':'service_down','hostname':'billing-01','message':'SSH listener unavailable'}}
        connection=Mock();connection.getresponse.return_value.status=202;connection.getresponse.return_value.read.return_value=b''
        with patch.object(n,'PinnedHTTPS',return_value=connection):
            result=n._http(channel,delivery)
        card=json.loads(connection.request.call_args.args[2])
        self.assertEqual(result['transport'],'teams')
        self.assertEqual(card['type'],'message')
        self.assertEqual(card['attachments'][0]['contentType'],'application/vnd.microsoft.card.adaptive')
        self.assertIn('billing-01',card['attachments'][0]['content']['body'][0]['text'])
        self.assertNotIn('not-real',json.dumps(card))
