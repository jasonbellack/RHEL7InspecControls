control "xccdf_mil.disa.stig_rule_SV-86857r3_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that all networked systems have SSH installed."
  desc  "
    Vulnerability Discussion: Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered.
    
    This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.
    
    Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, logical means (cryptography) do not have to be employed, and vice versa.
    
    Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188, SRG-OS-000425-GPOS-00189, SRG-OS-000426-GPOS-00190
    
    Documentable: false
    
  "
  impact 0.5
  describe package("openssh-server") do
    it { should be_installed }
  end
end
