import requests
import requests_mock


from BadDNS.lib.matcher import Matcher


def test_matcher_1():
    with requests_mock.Mocker() as rm:
        rm.get(
            f"https://baddns.com/test1",
            status_code=404,
            text="<html><p>Domain isn't configured</p><p>flexbe</p></html>",
        )
        rules = """
        matchers-condition: and
        matchers:

          - type: word
            condition: and
            words:
              - "Domain isn't configured"
              - "flexbe"

          - type: status
            status:
              - 404
        """
        m = Matcher(rules)
        r = requests.get("https://baddns.com/test1")
        assert m.is_match(r)


def test_matcher_2():
    with requests_mock.Mocker() as rm:
        rm.get(
            f"https://baddns.com/test2",
            status_code=302,
            text="<html><p>Content</p></html>",
            headers={"Foo": "offline.ghost.org"},
        )
        rules = """
        matchers-condition: and
        matchers:
          - type: word
            part: header
            words:
              - 'offline.ghost.org'

          - type: status
            status:
              - 302
        """
        m = Matcher(rules)
        r = requests.get("https://baddns.com/test2")
        assert m.is_match(r)


def test_matcher_3():
    with requests_mock.Mocker() as rm:
        rm.get(
            f"https://baddns.com/test3",
            status_code=302,
            text="<html><p>you&rsquo;re looking for doesn&rsquo;t exist</p></html>",
            headers={"Foo": "offline.ghost.org"},
        )
        rules = """
    matchers-condition: and
    matchers:
      - type: regex
        regex:
          - "(?:Company Not Found|you&rsquo;re looking for doesn&rsquo;t exist)"
        """
        m = Matcher(rules)
        r = requests.get("https://baddns.com/test3")
        assert m.is_match(r)
