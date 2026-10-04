import json
import pytest
from redaction import redact, InputError

@pytest.mark.parametrize('value,rule', [
 ('riya.shah@example.test','email'),('DEV+alerts@sub.example.test','email'),
 ('+91 90000 00001','indian_phone'),('90000-00002','indian_phone'),('919000000003','indian_phone'),('9000000004','indian_phone'),
 ('password="fictional two words"','credential'),("secret='hello world'",'credential'),('api_key=DEMO_NARMADA_PRIVATE','credential'),
 ('Authorization: Bearer abc.123.fake','bearer'),('sk_test_notarealsecret','token'),('ghp_abcdefghijkl','token'),('DEMO_FAKE_CREDENTIAL','token'),
 ('password="abc\\\"secret-tail"','credential'),('password="unterminated sensitive value','credential'),
 ('password="'+'x'*4000+'"','credential'),('api_key='+'x'*4000,'credential'),
])
def test_supported_patterns(value, rule):
    result = redact('prefix '+value+' suffix')
    assert result['counts'][rule] == 1
    assert value not in result['output']
    if 'secret-tail' in value:
        assert 'secret-tail' not in result['output']

@pytest.mark.parametrize('value', ['receipt=BAHI-204 status=200','192.0.2.18','1234567890','5000000000','time=09:30:00', 'value=2026091501', '<script>alert(1)</script>'])
def test_negative_corpus(value):
    assert redact(value)['output'] == value
    assert redact(value)['matches'] == 0

@pytest.mark.parametrize('value', [None, 42, '', ' ', '\x00test', 'x'*80001, '\n'.join('line' for _ in range(801))])
def test_input_limits(value):
    with pytest.raises(InputError): redact(value)

def test_jsonl_recursive_values_and_numeric_phones():
    result=redact(json.dumps({'phone':9000000001,'nested':[{'password': {'raw':'never-retain-me'}},'riya@example.test'],'safe':True}), 'jsonl')
    assert 'never-retain-me' not in result['output']
    assert '9000000001' not in result['output']
    assert 'riya@example.test' not in result['output']
    assert json.loads(result['output'])['safe'] is True
    assert result['counts']=={'credential':1,'email':1,'indian_phone':1}

@pytest.mark.parametrize('value', ['not json', '{"email":"secret@example.test"', '{"x":NaN}', '{"x":Infinity}', '['*20+'0'+']'*20])
def test_bad_json_has_safe_errors(value):
    with pytest.raises(InputError) as error: redact(value,'jsonl')
    assert value not in str(error.value)

def test_json_keys_are_also_redacted():
    assert 'riya@example.test' not in redact('{"riya@example.test":"ok"}', 'jsonl')['output']

def test_bad_mode():
    with pytest.raises(InputError): redact('hello','csv')

def test_bounded_oversized_output():
    with pytest.raises(InputError): redact('9000000001 '*7000)

def test_redaction_is_idempotent():
    output=redact('password=abc riya@example.test +91 90000 00001')['output']
    assert redact(output)['output']==output

def test_evaluation_corpus_reports_false_positives_and_misses():
    from evaluate import evaluate
    result=evaluate()
    assert result['cases']==20
    assert result['true_positive']==13 and result['true_negative']==7
    assert result['false_positive']==result['false_negative']==0

def test_jsonl_empty_lines_and_scalar_values():
    result=redact(' \ntrue\n42\n"riya@example.test"\n', 'jsonl')
    assert result['line_count']==3
    assert result['output'].splitlines()[:2]==['true','42']
