control "xccdf_mil.disa.stig_rule_SV-87041r3_rule" do
  title "The Red Hat Enterprise Linux operating system must have the required packages for multifactor authentication installed."
  desc  "
    Vulnerability Discussion: Using an authentication device, such as a CAC or token that is separate from the information system, ensures that even if the information system is compromised, that compromise will not affect credentials stored on the authentication device.
    
    Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD Common Access Card.
    
    A privileged account is defined as an information system account with authorizations of a privileged user.
    
    Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.
    
    This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of configuring the device itself (management).
    
    Requires further clarification from NIST.
    
    Satisfies: SRG-OS-000375-GPOS-00160, SRG-OS-000375-GPOS-00161, SRG-OS-000375-GPOS-00162
    
    Documentable: false
    
  "
  impact 0.5
  describe package("esc") do
    it { should be_installed }
  end
  describe package("pam_pkcs11") do
    it { should be_installed }
  end
  describe package("authconfig-gtk") do
    it { should be_installed }
  end
end
