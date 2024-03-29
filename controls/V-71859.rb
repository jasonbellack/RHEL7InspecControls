# encoding: UTF-8

control "xccdf_mil.disa.stig_rule_SV-86483r4_rule" do
    title "The Red Hat Enterprise Linux operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon."
    desc  "
      Vulnerability Discussion: Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.
      
      System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.
      
      The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters:
      
      \"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
      
      By using this IS (which includes any device attached to this IS), you consent to the following conditions:
      
      -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
      
      -At any time, the USG may inspect and seize data stored on this IS.
      
      -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
      
      -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
      
      -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.\"
      
      
      Satisfies: SRG-OS-000023-GPOS-00006, SRG-OS-000024-GPOS-00007, SRG-OS-000228-GPOS-00088
      
      Documentable: false
      
    "
  impact 0.5
    only_if { package("dconf").installed? }
    describe file("/etc/dconf/profile/user") do
      its("content") { should match(/^user-db:user\nsystem-db:local$/) }
    end
    files = command("find /etc/dconf/db -type f -maxdepth 2 -regex .\\*/\\^\\[0-9\\].\\*\\$ -and -regex /\\^/etc/dconf/db/\\[\\^/\\]\\+\\\\.d/\\?\\$").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\[org\/gnome\/login-screen\]([^\n]*\n+)+?banner-message-enable\s*=\s*true\s*$/m } do
      it { should_not be_empty }
    end
  end
