control "xccdf_mil.disa.stig_rule_SV-86575r2_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that the delay between logon prompts following a failed console logon attempt is at least four seconds."
  desc  "
    Vulnerability Discussion: Configuring the operating system to implement organization-wide security implementation guides and security checklists verifies compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.
    
    Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example, registry settings; account, file, and directory permission settings; and settings for functions, ports, protocols, services, and remote connections.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/login.defs") do
    its("content") { should match(/^[\s]*FAIL_DELAY[\s]+([^#\s]*)/) }
  end
  file("/etc/login.defs").content.to_s.scan(/^[\s]*FAIL_DELAY[\s]+([^#\s]*)/).flatten.each do |entry|
    describe entry do
      it { should cmp >= 4 }
    end
  end
end
