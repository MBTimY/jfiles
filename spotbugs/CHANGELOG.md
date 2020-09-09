# spotbugs analyzer changelog

## v2.11.0
- Add `scan.start_time`, `scan.end_time` and `scan.status` to report (!59)

## v2.10.1
- Upgrade go to version 1.15 (!57)

## v2.10.0
- Add scan object to report (!52)

## v2.9.0
- Switch to the MIT Expat license (!48)

## v2.8.1
- Update sdkman checksum (!50)
- Update Java 8 version (!50)
- Update Java 11 version (!50)

## v2.8.0
- Update logging to be standardized across analyzers (!47)

## v2.7.1
- Add self-signed ceritficates for java projects (!43)

## v2.7.0
- Add `COMPILE` environment variable to skip project compilation (!42)

## v2.6.1
- Remove `location.dependency` from the generated SAST report (!40)

## v2.6.0
- Bump spotbugs to 4.0.2, glibc to 2.31-r0, zlib to 1.3.11-4, grails to 4.0.3, maven to 3.6.3, sbt to 1.3.10, scala to 2.13.1

## v2.5.1
- Bump SDKMAN to 5.8.1+484, Java 8 to 8.0.252, Java 11 to 11.0.7

## v2.5.0
- Add `id` field to vulnerabilities in JSON report (!33)

## v2.4.2
- Fix bug incorrectly attributing SpotBugs vulnerability to FindSecBugs (!30)

## v2.4.1
- update gradle to 5.6 (!31)

## v2.4.0
- Add support for custom CA certs (!28)

## v2.3.6
- Fixes setting Java 11 after sdkman breaking update (!26)

## v2.3.5
- update java 8 defined in analyze.go to release 8.0.242 (!25)
- update java 11 defined in analyze.go to release 11.0.6 (!25)

## v2.3.4
- update java 8 to release 8.0.242 (!22)
- update java 11 to release 11.0.6 (!22)

## v2.3.3
- update sdkman to latest v5.7.4+362 (!21)

## v2.3.2
- update java 8 to patch release 8.0.232 (!16 @haynes)
- update java 11 to patch release 11.0.5 (!16 @haynes)
- update findsecbugs to 1.10.1 (!16 @haynes)
- update sdkman to latest version 5.7.4+362 (!16 @haynes)

## v2.3.1
- added `--batch-mode` to the default `MAVEN_CLI_OPTS` to reduce the logsize

## v2.3.0
- Add an environment variable `SAST_JAVA_VERSION` to specify which Java version to use (8, 11)
  - Default version remains Java 8
  - Specific versions of Java 8/11 can be set using `JAVA_8_VERSION` and `JAVA_11_VERSION`

## v2.2.3
- Fix report JSON compare keys (`cve`) non-uniqueness by including file path and line information into them

## v2.2.2
 - Switch primary `mvn`/`mvnw` build method from `compile` to `install`
 - Support builds on cross-referential multi-module projects

## v2.2.1
 - Update sdkman to latest version 5.7.3+337

## v2.2.0
 - Change default behavior to exit early with non-zero exit code if compilation fails
 - Introduce new `FAIL_NEVER` variable, to be set to `1` to ignore compilation failure

## v2.1.0
- Bump Spotbugs to [3.1.12](https://github.com/spotbugs/spotbugs/blob/3.1.12/CHANGELOG.md#3112---2019-02-28)
- Bump Find Sec Bugs to [1.9.0](https://github.com/find-sec-bugs/find-sec-bugs/releases/tag/version-1.9.0)

## v2.0.1
- Update common to v2.1.6

## v2.0.0
- Merge of the Maven, Gradle, Groovy and SBT analyzers with additional features:
  - Use the SpotBugs CLI for analysis.
  - Report correct source file paths.
  - Handle Maven multi module projects.
  - Only report vulnerabilities in source code files, ignore dependencies' libraries.
  - Add command line parameters and environment variable to set the paths of the Ant, Gradle, Maven, SBT and Java
    executables.
  - Add the `--mavenCliOpts` command line parameter and `MAVEN_CLI_OPTS` environment to pass arguments to Maven.
