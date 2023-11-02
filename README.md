cors-scanner
==

| Type          | Name                                   | payload                                                  | proof                                                                         |
| ------------- | -------------------------------------- | -------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Capability    | preflight-support                      | OPTIONS                                                  | 2xx                                                                           |
| Capability    | acao-subdomain-reflection              | Origin: https://nonexistent.target.com                   | Access-Control-Allow-Origin: https://nonexistent.target.com                   |
| Capability    | acao-subdomain-lf-injection            | Origin: https://non`<\n>`existent.target.com             | Access-Control-Allow-Origin: https://non`<\n>`existent.target.com             |
| Capability    | acao-subdomain-cr-injection            | Origin: https://non`<\r>`existent.target.com             | Access-Control-Allow-Origin: https://non`<\r>`existent.target.com             |
| Capability    | acao-port-reflection                   | Origin: https://target.com:1337                          | Access-Control-Allow-Origin: https://target.com:1337                          |
| Capability    | acao-port-lf-injection                 | Origin: https://target.com:13`<\n>`37                    | Access-Control-Allow-Origin: https://target.com:13`<\n>`37                    |
| Capability    | acao-port-cr-injection                 | Origin: https://target.com:13`<\r>`37                    | Access-Control-Allow-Origin: https://target.com:13`<\r>`37                    |
| Capability    | acao-wildcard                          |                                                          | Access-Control-Allow-Origin: *                                                |
| Capability    | acah-wildcard                          |                                                          | Access-Control-Allow-Headers: *                                               |
| Capability    | acam-wildcard                          |                                                          | Access-Control-Allow-Method: *                                                |
| Capability    | acah-reflection                        | Access-Control-Request-Headers: x-test                   | Access-Control-Allow-Headers: x-test                                          |
| Capability    | acam-reflection                        | Access-Control-Request-Method: test                      | Access-Control-Allow-Method: test                                             |
| Capability    | acah-lf-injection                      | Access-Control-Request-Headers: te`<\n>`st               | Access-Control-Allow-Headers: te`<\n>`st                                      |
| Capability    | acah-cr-injection                      | Access-Control-Request-Headers: te`<\r>`st               | Access-Control-Allow-Headers: te`<\r>`st                                      |
| Capability    | acam-lf-injection                      | Access-Control-Request-Method: te`<\n>`st                | Access-Control-Allow-Method: te`<\n>`st                                       |
| Capability    | acam-cr-injection                      | Access-Control-Request-Method: te`<\r>`st                | Access-Control-Allow-Method: te`<\r>`st                                       |
| Capability    | acao-fixed                             |                                                          | Access-Control-Allow-Origin: `<fixed-value>`                                  |
| Capability    | acam-fixed                             |                                                          | Access-Control-Allow-Method: `<fixed-value>`                                  |
| Capability    | acah-fixed                             |                                                          | Access-Control-Allow-Headers: `<fixed-value>`                                 |
| Capability    | aceh-fixed                             |                                                          | Access-Control-Expose-Headers: `<fixed-value>`                                |
| Misconfig     | acao-reflection                        | Origin: https://example.com                              | Access-Control-Allow-Origin: https://example.com                              |
| Misconfig     | acao-subdomain-reflection-without-vary | Origin: https://nonexistent.target.com                   | Access-Control-Allow-Origin: https://nonexistent.target.com                   |
| Misconfig     | acao-port-reflection-without-vary      | Origin: https://target.com:1337                          | Access-Control-Allow-Origin: https://target.com:1337                          |
| Misconfig     | acao-null-origin                       | Origin: null                                             | Access-Control-Allow-Origin: null                                             |
| Misconfig     | acao-http-origin                       | Origin: http://target.com                                | Access-Control-Allow-Origin: http://target.com                                |
| Misconfig     | acao-s3-trust                          | Origin: https://bucket-name.s3.`<region>`.amazonaws.com/ | Access-Control-Allow-Origin: https://bucket-name.s3.`<region>`.amazonaws.com/ |
| Misconfig     | acao-s3-trust                          | Origin: https://s3.`<region>`.amazonaws.com/             | Access-Control-Allow-Origin: https://s3.`<region>`.amazonaws.com/             |
| Vulnerability | acao-regex-dot-bypass                  | Origin: https://subZtarget.com                           | Access-Control-Allow-Origin: https://subZtarget.com                           |
| Vulnerability | acao-prefix-bypass                     | Origin: https://nonexistenttarget.com                    | Access-Control-Allow-Origin: https://nonexistenttarget.com                    |
| Vulnerability | acao-suffix-bypass                     | Origin: https://target.com.evil.com                      | Access-Control-Allow-Origin: https://target.com.evil.com                      |
| Vulnerability | acao-suffix-bypass                     | Origin: https://target.comevil.com                       | Access-Control-Allow-Origin: https://target.comevil.com                       |
| Vulnerability | acao-suffix-bypass                     | Origin: https://target.com`<special_char>`.evil.com      | Access-Control-Allow-Origin: https://target.com`<special_char>`.evil.com      |


**To Do**
- dynamic header generation without vary
- Unicode normalization bypasses?

### Extra Checks that Require Server-side Cache Poisoning

Allowed subdomain Bypass
- [ ] https://evil.com/example.com
- [ ] https://evil.com//example.com
- [ ] https://evil.com/://example.com
- [ ] https://evil.com/.example.com
- [ ] https://evil.com//.example.com
- [ ] https://evil.com/://.example.com

Allowed port Bypass
- [ ] https://example.com@evil.com
- [ ] https://example.com:@evil.com

