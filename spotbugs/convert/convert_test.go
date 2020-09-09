package convert

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/issue"
)

func TestConvert(t *testing.T) {
	in := `<BugCollection sequence='0' release='' analysisTimestamp='1527802705462' version='3.1.2' timestamp='1527802621000'>
	<Project projectName='java-maven'>
			<Jar>/Users/ogonzalez/dev/gitlab/gitlab-org/security-products/tests/sast/maven/target/classes</Jar>
			<AuxClasspathEntry>/Users/ogonzalez/.m2/repository/io/netty/netty/3.9.1.Final/netty-3.9.1.Final.jar</AuxClasspathEntry>
			<AuxClasspathEntry>/Users/ogonzalez/.m2/repository/org/apache/maven/maven-artifact/3.3.9/maven-artifact-3.3.9.jar</AuxClasspathEntry>
			<AuxClasspathEntry>/Users/ogonzalez/.m2/repository/org/codehaus/plexus/plexus-utils/3.0.22/plexus-utils-3.0.22.jar</AuxClasspathEntry>
			<AuxClasspathEntry>/Users/ogonzalez/.m2/repository/org/apache/commons/commons-lang3/3.4/commons-lang3-3.4.jar</AuxClasspathEntry>
			<AuxClasspathEntry>/Users/ogonzalez/.m2/repository/com/fasterxml/jackson/core/jackson-databind/2.9.2/jackson-databind-2.9.2.jar</AuxClasspathEntry>
			<AuxClasspathEntry>/Users/ogonzalez/.m2/repository/com/fasterxml/jackson/core/jackson-annotations/2.9.0/jackson-annotations-2.9.0.jar</AuxClasspathEntry>
			<AuxClasspathEntry>/Users/ogonzalez/.m2/repository/com/fasterxml/jackson/core/jackson-core/2.9.2/jackson-core-2.9.2.jar</AuxClasspathEntry>
			<Plugin
					id='com.h3xstream.findsecbugs' enabled='true'></Plugin>
			<SrcDir>/Users/ogonzalez/dev/gitlab/gitlab-org/security-products/tests/sast/maven/src/main/java</SrcDir>
			<WrkDir>/Users/ogonzalez/dev/gitlab/gitlab-org/security-products/tests/sast/maven/target</WrkDir>
	</Project>
	<BugInstance instanceOccurrenceNum='0' instanceHash='e6449b89335daf53c0db4c0219bc1634' cweid='353' rank='10' abbrev='CIPINT'
			category='SECURITY' priority='1' type='CIPHER_INTEGRITY' instanceOccurrenceMax='0'>
			<ShortMessage>Cipher with no integrity</ShortMessage>
			<LongMessage>The cipher does not provide data integrity</LongMessage>
			<Class classname='com.gitlab.security_products.tests.App'
					primary='true'>
					<SourceLine classname='com.gitlab.security_products.tests.App' start='14' end='48' sourcepath='src/main/java/com/gitlab/security_products/tests/App.java'
							sourcefile='App.java'>
							<Message>At App.java:[lines 14-48]</Message>
					</SourceLine>
					<Message>In class com.gitlab.security_products.tests.App</Message>
			</Class>
			<Method isStatic='false' classname='com.gitlab.security_products.tests.App' signature='()V' name='insecureCypher'
					primary='true'>
					<SourceLine endBytecode='180' classname='com.gitlab.security_products.tests.App' start='29' end='37' sourcepath='src/main/java/com/gitlab/security_products/tests/App.java'
							sourcefile='App.java' startBytecode='0'></SourceLine>
					<Message>In method com.gitlab.security_products.tests.App.insecureCypher()</Message>
			</Method>
			<SourceLine endBytecode='2' classname='com.gitlab.security_products.tests.App' start='29' end='29' sourcepath='src/main/java/com/gitlab/security_products/tests/App.java'
					sourcefile='App.java' startBytecode='2' primary='true'>
					<Message>At App.java:[line 29]</Message>
			</SourceLine>
	</BugInstance>
	<BugInstance instanceOccurrenceNum='0' instanceHash='818bf5dacb291e15d9e6dc3c5ac32178' cweid='330' rank='12' abbrev='SECPR'
			category='SECURITY' priority='2' type='PREDICTABLE_RANDOM' instanceOccurrenceMax='0'>
			<ShortMessage>Predictable pseudorandom number generator</ShortMessage>
			<LongMessage>The use of java.util.Random is predictable</LongMessage>
			<Class classname='com.gitlab.security_products.tests.App'
					primary='true'>
					<SourceLine classname='com.gitlab.security_products.tests.App' start='14' end='48' sourcepath='src/main/java/com/gitlab/security_products/tests/App.java'
							sourcefile='App.java'>
							<Message>At App.java:[lines 14-48]</Message>
					</SourceLine>
					<Message>In class com.gitlab.security_products.tests.App</Message>
			</Class>
			<Method isStatic='false' classname='com.gitlab.security_products.tests.App' signature='()Ljava/lang/String;' name='generateSecretToken2'
					primary='true'>
					<SourceLine endBytecode='71' classname='com.gitlab.security_products.tests.App' start='47' end='48' sourcepath='src/main/java/com/gitlab/security_products/tests/App.java'
							sourcefile='App.java' startBytecode='0'></SourceLine>
					<Message>In method com.gitlab.security_products.tests.App.generateSecretToken2()</Message>
			</Method>
			<SourceLine endBytecode='4' classname='com.gitlab.security_products.tests.App' start='47' end='47' sourcepath='src/main/java/com/gitlab/security_products/tests/App.java'
					sourcefile='App.java' startBytecode='4' primary='true'>
					<Message>At App.java:[line 47]</Message>
			</SourceLine>
			<String value='java.util.Random'>
					<Message>Value java.util.Random</Message>
			</String>
	</BugInstance>

	<BugPattern cweid='353' abbrev='CIPINT' category='SECURITY' type='CIPHER_INTEGRITY'>
			<ShortDescription>Cipher with no integrity</ShortDescription>
			<Details>

					&lt;p&gt; The ciphertext produced is susceptible to alteration by an adversary. This mean that the cipher provides no way
					to detect that the data has been tampered with. If the ciphertext can be controlled by an attacker, it could
					be altered without detection. &lt;/p&gt; &lt;p&gt; The solution is to used a cipher that includes a Hash based
					Message Authentication Code (HMAC) to sign the data. Combining a HMAC function to the existing cipher is prone
					to error &lt;sup&gt;&lt;a href="http://www.thoughtcrime.org/blog/the-cryptographic-doom-principle/"&gt;[1]&lt;/a&gt;&lt;/sup&gt;.
					Specifically, it is always recommended that you be able to verify the HMAC first, and only if the data is unmodified,
					do you then perform any cryptographic functions on the data. &lt;/p&gt; &lt;p&gt;The following modes are vulnerable
					because they don't provide a HMAC:&lt;br/&gt; - CBC&lt;br/&gt; - OFB&lt;br/&gt; - CTR&lt;br/&gt; - ECB&lt;br/&gt;&lt;br/&gt;
					The following snippets code are some examples of vulnerable code.&lt;br/&gt;&lt;br/&gt; &lt;b&gt;Code at risk:&lt;/b&gt;&lt;br/&gt;
					&lt;i&gt;AES in CBC mode&lt;/i&gt;&lt;br/&gt; &lt;pre&gt;Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
					c.init(Cipher.ENCRYPT_MODE, k, iv); byte[] cipherText = c.doFinal(plainText);&lt;/pre&gt; &lt;br/&gt; &lt;i&gt;Triple
					DES with ECB mode&lt;/i&gt;&lt;br/&gt; &lt;pre&gt;Cipher c = Cipher.getInstance("DESede/ECB/PKCS5Padding"); c.init(Cipher.ENCRYPT_MODE,
					k, iv); byte[] cipherText = c.doFinal(plainText);&lt;/pre&gt; &lt;/p&gt; &lt;p&gt; &lt;b&gt;Solution:&lt;/b&gt;
					&lt;pre&gt;Cipher c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.ENCRYPT_MODE, k, iv); byte[] cipherText
					= c.doFinal(plainText);&lt;/pre&gt; &lt;/p&gt; &lt;p&gt; In the example solution above, the GCM mode introduces
					an HMAC into the resulting encrypted data, providing integrity of the result. &lt;/p&gt; &lt;br/&gt; &lt;p&gt;
					&lt;b&gt;References&lt;/b&gt;&lt;br/&gt; &lt;a href="http://en.wikipedia.org/wiki/Authenticated_encryption"&gt;Wikipedia:
					Authenticated encryption&lt;/a&gt;&lt;br/&gt; &lt;a href="http://csrc.nist.gov/groups/ST/toolkit/BCM/modes_development.html#01"&gt;NIST:
					Authenticated Encryption Modes&lt;/a&gt;&lt;br/&gt; &lt;a href="http://www.thoughtcrime.org/blog/the-cryptographic-doom-principle/"&gt;Moxie
					Marlinspike's blog: The Cryptographic Doom Principle&lt;/a&gt;&lt;br/&gt; &lt;a href="http://cwe.mitre.org/data/definitions/353.html"&gt;CWE-353:
					Missing Support for Integrity Check&lt;/a&gt; &lt;/p&gt;

			</Details>
	</BugPattern>
	<BugPattern cweid='330' abbrev='SECPR' category='SECURITY' type='PREDICTABLE_RANDOM'>
			<ShortDescription>Predictable pseudorandom number generator</ShortDescription>
			<Details>

					&lt;p&gt;The use of a predictable random value can lead to vulnerabilities when used in certain security critical contexts.
					For example, when the value is used as:&lt;/p&gt; &lt;ul&gt; &lt;li&gt;a CSRF token: a predictable token can
					lead to a CSRF attack as an attacker will know the value of the token&lt;/li&gt; &lt;li&gt;a password reset token
					(sent by email): a predictable password token can lead to an account takeover, since an attacker will guess the
					URL of the change password form&lt;/li&gt; &lt;li&gt;any other secret value&lt;/li&gt; &lt;/ul&gt; &lt;p&gt;
					A quick fix could be to replace the use of &lt;b&gt;java.util.Random&lt;/b&gt; with something stronger, such
					as &lt;b&gt;java.security.SecureRandom&lt;/b&gt;. &lt;/p&gt; &lt;p&gt; &lt;b&gt;Vulnerable Code:&lt;/b&gt;&lt;br/&gt;
					&lt;pre&gt;String generateSecretToken() { Random r = new Random(); return Long.toHexString(r.nextLong()); }&lt;/pre&gt;
					&lt;/p&gt; &lt;p&gt; &lt;b&gt;Solution:&lt;/b&gt; &lt;pre&gt;import org.apache.commons.codec.binary.Hex; String
					generateSecretToken() { SecureRandom secRandom = new SecureRandom(); byte[] result = new byte[32]; secRandom.nextBytes(result);
					return Hex.encodeHexString(result); }&lt;/pre&gt; &lt;/p&gt; &lt;br/&gt; &lt;p&gt; &lt;b&gt;References&lt;/b&gt;&lt;br/&gt;
					&lt;a href="http://jazzy.id.au/default/2010/09/20/cracking_random_number_generators_part_1.html"&gt;Cracking
					Random Number Generators - Part 1 (http://jazzy.id.au)&lt;/a&gt;&lt;br/&gt; &lt;a href="https://www.securecoding.cert.org/confluence/display/java/MSC02-J.+Generate+strong+random+numbers"&gt;CERT:
					MSC02-J. Generate strong random numbers&lt;/a&gt;&lt;br/&gt; &lt;a href="http://cwe.mitre.org/data/definitions/330.html"&gt;CWE-330:
					Use of Insufficiently Random Values&lt;/a&gt;&lt;br/&gt; &lt;a href="http://blog.h3xstream.com/2014/12/predicting-struts-csrf-token-cve-2014.html"&gt;Predicting
					Struts CSRF Token (Example of real-life vulnerability and exploitation)&lt;/a&gt; &lt;/p&gt;

			</Details>
	</BugPattern>
	<BugCode abbrev='SECPR'>
			<Description>Predictable Pseudo Random Generator</Description>
	</BugCode>
	<BugCode abbrev='CIPINT'>
			<Description>Cipher with no integrity</Description>
	</BugCode>
	<Errors missingClasses='0' errors='0'></Errors>
	<FindBugsSummary num_packages='1' total_classes='1' priority_1='2' priority_2='2' total_size='23' clock_seconds='1.65'
			referenced_classes='22' vm_version='9.0.4+11' total_bugs='4' java_version='9.0.4' gc_seconds='0.04' alloc_mbytes='512.00'
			cpu_seconds='7.38' peak_mbytes='223.05' timestamp='Thu, 31 May 2018 17:37:01 -0400'>
			<FileStats path='com/gitlab/security_products/tests/App.java' size='23' bugHash='fd991029794b59d2b25607135fecc18e' bugCount='4'></FileStats>
			<PackageStats package='com.gitlab.security_products.tests' priority_1='2' total_bugs='4' priority_2='2'
					total_size='23' total_types='1'>
					<ClassStats bugs='4' size='23' priority_1='2' priority_2='2' interface='false' sourceFile='App.java' class='com.gitlab.security_products.tests.App'></ClassStats>
			</PackageStats>
			<FindBugsProfile>
					<ClassProfile avgMicrosecondsPerInvocation='636' totalMilliseconds='271' name='edu.umd.cs.findbugs.classfile.engine.ClassInfoAnalysisEngine'
							maxMicrosecondsPerInvocation='18567' standardDeviationMicrosecondsPerInvocation='1453' invocations='426'></ClassProfile>
					<ClassProfile avgMicrosecondsPerInvocation='193' totalMilliseconds='83' name='edu.umd.cs.findbugs.classfile.engine.ClassDataAnalysisEngine'
							maxMicrosecondsPerInvocation='5290' standardDeviationMicrosecondsPerInvocation='325' invocations='428'></ClassProfile>
					<ClassProfile avgMicrosecondsPerInvocation='3214' totalMilliseconds='70' name='edu.umd.cs.findbugs.detect.FieldItemSummary'
							maxMicrosecondsPerInvocation='13033' standardDeviationMicrosecondsPerInvocation='3429' invocations='22'></ClassProfile>
					<ClassProfile avgMicrosecondsPerInvocation='2100' totalMilliseconds='46' name='edu.umd.cs.findbugs.detect.FunctionsThatMightBeMistakenForProcedures'
							maxMicrosecondsPerInvocation='25285' standardDeviationMicrosecondsPerInvocation='5277' invocations='22'></ClassProfile>
					<ClassProfile avgMicrosecondsPerInvocation='1972' totalMilliseconds='43' name='edu.umd.cs.findbugs.detect.FindNoSideEffectMethods'
							maxMicrosecondsPerInvocation='6763' standardDeviationMicrosecondsPerInvocation='2020' invocations='22'></ClassProfile>
					<ClassProfile avgMicrosecondsPerInvocation='6230' totalMilliseconds='37' name='edu.umd.cs.findbugs.classfile.engine.bcel.MethodGenFactory'
							maxMicrosecondsPerInvocation='35868' standardDeviationMicrosecondsPerInvocation='13257' invocations='6'></ClassProfile>
					<ClassProfile avgMicrosecondsPerInvocation='435' totalMilliseconds='36' name='edu.umd.cs.findbugs.OpcodeStack$JumpInfoFactory'
							maxMicrosecondsPerInvocation='2364' standardDeviationMicrosecondsPerInvocation='441' invocations='84'></ClassProfile>
					<ClassProfile avgMicrosecondsPerInvocation='85' totalMilliseconds='33' name='edu.umd.cs.findbugs.util.TopologicalSort'
							maxMicrosecondsPerInvocation='1387' standardDeviationMicrosecondsPerInvocation='172' invocations='393'></ClassProfile>
					<ClassProfile avgMicrosecondsPerInvocation='490' totalMilliseconds='28' name='edu.umd.cs.findbugs.classfile.engine.bcel.JavaClassAnalysisEngine'
							maxMicrosecondsPerInvocation='13447' standardDeviationMicrosecondsPerInvocation='1797' invocations='58'></ClassProfile>
					<ClassProfile avgMicrosecondsPerInvocation='1100' totalMilliseconds='24' name='edu.umd.cs.findbugs.detect.NoteDirectlyRelevantTypeQualifiers'
							maxMicrosecondsPerInvocation='5539' standardDeviationMicrosecondsPerInvocation='1349' invocations='22'></ClassProfile>
					<ClassProfile avgMicrosecondsPerInvocation='1001' totalMilliseconds='22' name='edu.umd.cs.findbugs.detect.OverridingEqualsNotSymmetrical'
							maxMicrosecondsPerInvocation='9152' standardDeviationMicrosecondsPerInvocation='1977' invocations='22'></ClassProfile>
					<ClassProfile avgMicrosecondsPerInvocation='853' totalMilliseconds='18' name='edu.umd.cs.findbugs.detect.BuildStringPassthruGraph'
							maxMicrosecondsPerInvocation='6601' standardDeviationMicrosecondsPerInvocation='1391' invocations='22'></ClassProfile>
					<ClassProfile avgMicrosecondsPerInvocation='822' totalMilliseconds='18' name='edu.umd.cs.findbugs.detect.BuildObligationPolicyDatabase'
							maxMicrosecondsPerInvocation='4035' standardDeviationMicrosecondsPerInvocation='1086' invocations='22'></ClassProfile>
					<ClassProfile avgMicrosecondsPerInvocation='2639' totalMilliseconds='15' name='edu.umd.cs.findbugs.classfile.engine.bcel.ValueNumberDataflowFactory'
							maxMicrosecondsPerInvocation='12584' standardDeviationMicrosecondsPerInvocation='4473' invocations='6'></ClassProfile>
			</FindBugsProfile>
	</FindBugsSummary>
	<ClassFeatures></ClassFeatures>
	<History></History>
</BugCollection>`

	var scanner = issue.Scanner{
		ID:   "find_sec_bugs",
		Name: "Find Security Bugs",
	}

	r := strings.NewReader(in)
	want := &issue.Report{
		Version: issue.CurrentVersion(),
		Vulnerabilities: []issue.Issue{
			{
				Category:    issue.CategorySast,
				Scanner:     scanner,
				Name:        "Cipher with no integrity",
				Message:     "Cipher with no integrity",
				Description: "The cipher does not provide data integrity",
				CompareKey:  "e6449b89335daf53c0db4c0219bc1634:CIPHER_INTEGRITY:src/main/java/com/gitlab/security_products/tests/App.java:29",
				Severity:    issue.SeverityLevelMedium,
				Confidence:  issue.ConfidenceLevelHigh,
				Location: issue.Location{
					File:      "app/src/main/java/com/gitlab/security_products/tests/App.java",
					LineStart: 29,
					LineEnd:   29,
					Class:     "com.gitlab.security_products.tests.App",
					Method:    "insecureCypher",
				},
				Identifiers: []issue.Identifier{
					{
						Type:  "find_sec_bugs_type",
						Name:  "Find Security Bugs-CIPHER_INTEGRITY",
						Value: "CIPHER_INTEGRITY",
						URL:   "https://find-sec-bugs.github.io/bugs.htm#CIPHER_INTEGRITY",
					},
					{
						Type:  "cwe",
						Name:  "CWE-353",
						Value: "353",
						URL:   "https://cwe.mitre.org/data/definitions/353.html",
					},
				},
			},
			{
				Category:    issue.CategorySast,
				Scanner:     scanner,
				Name:        "Predictable pseudorandom number generator",
				Message:     "Predictable pseudorandom number generator",
				Description: "The use of java.util.Random is predictable",
				CompareKey:  "818bf5dacb291e15d9e6dc3c5ac32178:PREDICTABLE_RANDOM:src/main/java/com/gitlab/security_products/tests/App.java:47",
				Severity:    issue.SeverityLevelMedium,
				Confidence:  issue.ConfidenceLevelMedium,
				Location: issue.Location{
					File:      "app/src/main/java/com/gitlab/security_products/tests/App.java",
					LineStart: 47,
					LineEnd:   47,
					Class:     "com.gitlab.security_products.tests.App",
					Method:    "generateSecretToken2",
				},
				Identifiers: []issue.Identifier{
					{
						Type:  "find_sec_bugs_type",
						Name:  "Find Security Bugs-PREDICTABLE_RANDOM",
						Value: "PREDICTABLE_RANDOM",
						URL:   "https://find-sec-bugs.github.io/bugs.htm#PREDICTABLE_RANDOM",
					},
					{
						Type:  "cwe",
						Name:  "CWE-330",
						Value: "330",
						URL:   "https://cwe.mitre.org/data/definitions/330.html",
					},
				},
			},
		},
		DependencyFiles: []issue.DependencyFile{},
		Remediations:    []issue.Remediation{},
	}
	got, err := Convert(r, "app")
	if err != nil {
		t.Fatal(err)
	}

	require.Equal(t, want, got)
}
