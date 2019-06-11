control "xccdf_mil.disa.stig_rule_SV-86849r4_rule" do
  title "The Red Hat Enterprise Linux operating system must display the Standard Mandatory DoD Notice and Consent Banner immediately prior to, or as part of, remote access logon prompts."
  desc  "
    Vulnerability Discussion: Display of a standardized and approved use notification before granting access to the publicly accessible operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.
    
    System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.
    
    The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters:
    
    \"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
    
    By using this IS (which includes any device attached to this IS), you consent to the following conditions:
    
    -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
    
    -At any time, the USG may inspect and seize data stored on this IS.
    
    -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
    
    -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
    
    -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.\"
    
    Satisfies: SRG-OS-000023-GPOS-00006, SRG-OS-000024-GPOS-00007 , SRG-OS-000228-GPOS-00088
    
    Documentable: false
    
  "
  impact 0.5
  only_if { package("openssh-server").installed? }
  
  describe sshd_config("/etc/ssh/sshd_config") do
    its ("Banner") { should_not be_nil }
  end
  banner_file = sshd_config("/etc/ssh/sshd_config").Banner

  required_banner_message = /^(\\n|\s)*You\s+are\s+accessing\s+a\s+U\.S\.\s+Government\s+\(USG\)\s+Information\s+System\s+\(IS\)\s+that\s+is\s+provided\s+for\s+USG-authorized\s+use\s+only\.\s*By\s+using\s+this\s+IS\s+\(which\s+includes\s+any\s+device\s+attached\s+to\s+this\s+IS\),\s+you\s+consent\s+to\s+the\s+following\s+conditions\:\s*(\\n|\n)+\s*-The\s+USG\s+routinely\s+intercepts\s+and\s+monitors\s+communications\s+on\s+this\s+IS\s+for\s+purposes\s+including,\s+but\s+not\s+limited\s+to,\s+penetration\s+testing,\s+COMSEC\s+monitoring,\s+network\s+operations\s+and\s+defense,\s+personnel\s+misconduct\s+\(PM\),\s+law\s+enforcement\s+\(LE\),\s+and\s+counterintelligence\s+\(CI\)\s+investigations\.\s*(\\n|\n)+\s*-At\s+any\s+time,\s+the\s+USG\s+may\s+inspect\s+and\s+seize\s+data\s+stored\s+on\s+this\s+IS\.\s*(\\n|\n)+\s*-Communications\s+using,\s+or\s+data\s+stored\s+on,\s+this\s+IS\s+are\s+not\s+private,\s+are\s+subject\s+to\s+routine\s+monitoring,\s+interception,\s+and\s+search,\s+and\s+may\s+be\s+disclosed\s+or\s+used\s+for\s+any\s+USG-authorized\s+purpose\.\s*(\\n|\n)+\s*-This\s+IS\s+includes\s+security\s+measures\s+\(e\.g\.,\s+authentication\s+and\s+access\s+controls\)\s+to\s+protect\s+USG\s+interests--not\s+for\s+your\s+personal\s+benefit\s+or\s+privacy\.\s*(\\n|\n)+\s*-Notwithstanding\s+the\s+above,\s+using\s+this\s+IS\s+does\s+not\s+constitute\s+consent\s+to\s+PM,\s+LE\s+or\s+CI\s+investigative\s+searching\s+or\s+monitoring\s+of\s+the\s+content\s+of\s+privileged\s+communications,\s+or\s+work\s+product,\s+related\s+to\s+personal\s+representation\s+or\s+services\s+by\s+attorneys,\s+psychotherapists,\s+or\s+clergy,\s+and\s+their\s+assistants\.\s+Such\s+communications\s+and\s+work\s+product\s+are\s+private\s+and\s+confidential\.\s+See\s+User\s+Agreement\s+for\s+details\.$/
  
  describe file(banner_file) do
    it { should exist }
    its("content") { should match(required_banner_message) }
  end
  matching_text = file(banner_file).content.match(required_banner_message) || ["file does not match banner"]
  describe matching_text[0] do
    it { should eq file(banner_file).content.strip }
  end
end
