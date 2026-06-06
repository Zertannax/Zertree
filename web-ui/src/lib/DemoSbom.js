export const DEMO_SBOM = {
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:12345678-1234-1234-1234-123456789012",
  "version": 1,
  "metadata": {
    "timestamp": "2024-01-15T10:30:00Z",
    "tools": [
      {
        "vendor": "zertree",
        "name": "zertree-cli",
        "version": "0.1.0"
      }
    ]
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:npm/lodash@4.17.21",
      "name": "lodash",
      "version": "4.17.21",
      "description": "A modern JavaScript utility library delivering modularity, performance & extras.",
      "purl": "pkg:npm/lodash@4.17.21",
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ],
      "publisher": "John-David Dalton"
    },
    {
      "type": "library",
      "bom-ref": "pkg:npm/express@4.18.2",
      "name": "express",
      "version": "4.18.2",
      "description": "Fast, unopinionated, minimalist web framework for Node.js",
      "purl": "pkg:npm/express@4.18.2",
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ],
      "publisher": "TJ Holowaychuk"
    },
    {
      "type": "library",
      "bom-ref": "pkg:npm/react@18.2.0",
      "name": "react",
      "version": "18.2.0",
      "description": "A JavaScript library for building user interfaces",
      "purl": "pkg:npm/react@18.2.0",
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ],
      "publisher": "Meta"
    },
    {
      "type": "library",
      "bom-ref": "pkg:npm/axios@1.6.0",
      "name": "axios",
      "version": "1.6.0",
      "description": "Promise based HTTP client for the browser and node.js",
      "purl": "pkg:npm/axios@1.6.0",
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ],
      "publisher": "Matt Zabriskie"
    },
    {
      "type": "library",
      "bom-ref": "pkg:npm/webpack@5.89.0",
      "name": "webpack",
      "version": "5.89.0",
      "description": "A bundler for javascript and friends",
      "purl": "pkg:npm/webpack@5.89.0",
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ],
      "publisher": "Tobias Koppers"
    },
    {
      "type": "library",
      "bom-ref": "pkg:npm/moment@2.29.4",
      "name": "moment",
      "version": "2.29.4",
      "description": "Parse, manipulate, and display dates",
      "purl": "pkg:npm/moment@2.29.4",
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ],
      "publisher": "Iskren Ivov Chernev"
    },
    {
      "type": "library",
      "bom-ref": "pkg:npm/jest@29.7.0",
      "name": "jest",
      "version": "29.7.0",
      "description": "Delightful JavaScript Testing",
      "purl": "pkg:npm/jest@29.7.0",
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ],
      "publisher": "Meta"
    },
    {
      "type": "library",
      "bom-ref": "pkg:npm/typescript@5.3.3",
      "name": "typescript",
      "version": "5.3.3",
      "description": "TypeScript is a superset of JavaScript",
      "purl": "pkg:npm/typescript@5.3.3",
      "licenses": [
        {
          "license": {
            "id": "Apache-2.0"
          }
        }
      ],
      "publisher": "Microsoft"
    },
    {
      "type": "library",
      "bom-ref": "pkg:npm/eslint@8.56.0",
      "name": "eslint",
      "version": "8.56.0",
      "description": "An AST-based pattern checker for JavaScript",
      "purl": "pkg:npm/eslint@8.56.0",
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ],
      "publisher": "Nicholas C. Zakas"
    },
    {
      "type": "library",
      "bom-ref": "pkg:npm/d3@7.8.5",
      "name": "d3",
      "version": "7.8.5",
      "description": "Bring data to life with SVG, Canvas and HTML",
      "purl": "pkg:npm/d3@7.8.5",
      "licenses": [
        {
          "license": {
            "id": "ISC"
          }
        }
      ],
      "publisher": "Mike Bostock"
    },
    {
      "type": "library",
      "bom-ref": "pkg:npm/svelte@4.2.0",
      "name": "svelte",
      "version": "4.2.0",
      "description": "Cybernetically enhanced web apps",
      "purl": "pkg:npm/svelte@4.2.0",
      "licenses": [
        {
          "license": {
            "name": "MIT AND Apache-2.0"
          }
        }
      ],
      "publisher": "Rich Harris"
    },
    {
      "type": "library",
      "bom-ref": "pkg:npm/bootstrap@5.3.2",
      "name": "bootstrap",
      "version": "5.3.2",
      "description": "Popular HTML, CSS, and JS library",
      "purl": "pkg:npm/bootstrap@5.3.2",
      "licenses": [
        {
          "license": {
            "name": "GPL-3.0-only OR MIT"
          }
        }
      ],
      "publisher": "Twitter"
    },
    {
      "type": "library",
      "bom-ref": "pkg:npm/next@14.0.4",
      "name": "next",
      "version": "14.0.4",
      "description": "The React Framework for the Web",
      "purl": "pkg:npm/next@14.0.4",
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ],
      "publisher": "Vercel"
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:npm/react@18.2.0",
      "dependsOn": [
        "pkg:npm/lodash@4.17.21"
      ]
    },
    {
      "ref": "pkg:npm/next@14.0.4",
      "dependsOn": [
        "pkg:npm/react@18.2.0",
        "pkg:npm/axios@1.6.0"
      ]
    },
    {
      "ref": "pkg:npm/express@4.18.2",
      "dependsOn": [
        "pkg:npm/lodash@4.17.21"
      ]
    },
    {
      "ref": "pkg:npm/webpack@5.89.0",
      "dependsOn": [
        "pkg:npm/lodash@4.17.21"
      ]
    },
    {
      "ref": "pkg:npm/jest@29.7.0",
      "dependsOn": [
        "pkg:npm/lodash@4.17.21"
      ]
    },
    {
      "ref": "pkg:npm/eslint@8.56.0",
      "dependsOn": [
        "pkg:npm/lodash@4.17.21"
      ]
    },
    {
      "ref": "pkg:npm/d3@7.8.5",
      "dependsOn": [
        "pkg:npm/lodash@4.17.21"
      ]
    },
    {
      "ref": "pkg:npm/svelte@4.2.0",
      "dependsOn": [
        "pkg:npm/lodash@4.17.21"
      ]
    },
    {
      "ref": "pkg:npm/bootstrap@5.3.2",
      "dependsOn": [
        "pkg:npm/lodash@4.17.21"
      ]
    }
  ]
};

export const MOCK_VULNS = {
  "pkg:npm/lodash@4.17.21": [
    {
      "id": "CVE-2021-23337",
      "severity": "HIGH",
      "cvss_score": 7.2,
      "epss_score": 0.485,
      "fixed_version": "4.17.22",
      "description": "Prototype pollution vulnerability in lodash before 4.17.21 allows attackers to cause a denial of service or execute arbitrary code via zipObjectDeep, defaultsDeep, or merge."
    },
    {
      "id": "CVE-2020-8203",
      "severity": "MEDIUM",
      "cvss_score": 5.3,
      "epss_score": 0.125,
      "fixed_version": "4.17.16",
      "description": "Prototype pollution vulnerability in lodash before 4.17.16 allows attackers to inject properties onto Object.prototype."
    }
  ],
  "pkg:npm/axios@1.6.0": [
    {
      "id": "CVE-2023-45857",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      "epss_score": 0.892,
      "fixed_version": "1.6.1",
      "description": "Axios v1.6.0 contains a Server-Side Request Forgery (SSRF) vulnerability due to improper handling of redirects with relative paths."
    }
  ],
  "pkg:npm/express@4.18.2": [
    {
      "id": "CVE-2024-29041",
      "severity": "MEDIUM",
      "cvss_score": 6.5,
      "epss_score": 0.045,
      "fixed_version": "4.19.2",
      "description": "Express.js vulnerable to open redirect when using relative paths in res.redirect() under specific proxy headers."
    }
  ],
  "pkg:npm/moment@2.29.4": [
    {
      "id": "CVE-2022-31129",
      "severity": "HIGH",
      "cvss_score": 7.5,
      "epss_score": 0.185,
      "fixed_version": "2.29.5",
      "description": "Regular Expression Denial of Service (ReDoS) vulnerability in moment.js allows remote attackers to hang the event loop."
    }
  ]
};
