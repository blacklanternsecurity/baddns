import httpx
from pytest_httpx import HTTPXMock


from baddns.lib.matcher import Matcher


def test_matcher_1(httpx_mock):
    httpx_mock.add_response(
        url="https://baddns.com/test1",
        status_code=404,
        text="<html><p>Domain isn't configured</p><p>flexbe</p></html>",
    )
    rules = """
identifiers:
  cnames: []
  ips: []
  nameservers: []
  not_cnames: []
matcher_rule:
  matchers:
  - dsl:
    - Host != ip
    type: dsl
  - condition: and
    part: body
    type: word
    words:
    - Domain isn't configured
    - flexbe
  - status: 404
    type: status
  matchers-condition: and
mode: http
service_name: Flexbe Subdomain Takeover
source: nucleitemplates
    """
    m = Matcher(rules)
    r = httpx.get("https://baddns.com/test1")
    assert m.is_match(r)


def test_matcher_2(httpx_mock):
    httpx_mock.add_response(
        url="https://baddns.com/test2",
        status_code=302,
        text="<html><p>Content</p></html>",
        headers={"Foo": "offline.ghost.org"},
    )
    rules = """
  identifiers:
    cnames: []
    ips: []
    nameservers: []
    not_cnames: []
  matcher_rule:
    matchers:
    - dsl:
      - Host != ip
      type: dsl
    - condition: and
      part: header
      type: word
      words:
      - offline.ghost.org
    - status: 302
      type: status
    matchers-condition: and
  mode: http
  service_name: ghost takeover detection
  source: nucleitemplates
    """
    m = Matcher(rules)
    r = httpx.get("https://baddns.com/test2")
    assert m.is_match(r)


def test_matcher_3(httpx_mock):
    httpx_mock.add_response(
        url="https://baddns.com/test3",
        status_code=302,
        text="<html><p>you&rsquo;re looking for doesn&rsquo;t exist</p></html>",
        headers={"Foo": "offline.ghost.org"},
    )
    rules = """
  identifiers:
    cnames: []
    ips: []
    nameservers: []
    not_cnames: []
  matcher_rule:
    matchers:
    - dsl:
      - Host != ip
      type: dsl
    - regex:
      - (?:Company Not Found|you&rsquo;re looking for doesn&rsquo;t exist)
      type: regex
    matchers-condition: and
  mode: http
  service_name: worksites takeover detection
  source: nucleitemplates
        """
    m = Matcher(rules)
    r = httpx.get("https://baddns.com/test3")
    assert m.is_match(r)
