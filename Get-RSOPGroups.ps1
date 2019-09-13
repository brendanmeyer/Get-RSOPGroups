


function Get-RSOPGroups
{
	[CmdletBinding()]
	param(
		[Parameter(ParameterSetName='Computer')]
		[Switch]$Computer,
		
		[Parameter(ParameterSetName='User')]
		[Switch]$User,
		
		[Parameter(ParameterSetName='User')]
		[System.Security.Principal.SecurityIdentifier]$UserSID = $null
	)

	begin
	{
		# Add Native Win32 API functions
		Add-Type @"
using System;
using System.Collections.Generic;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

public class RSOPGroups
{
	enum Win32Err
	{
		NO_ERROR = 0,
		ERROR_INSUFFICIENT_BUFFER = 122
	}

	enum SID_NAME_USE
	{
		SidTypeUser = 1,
		SidTypeGroup,
		SidTypeDomain,
		SidTypeAlias,
		SidTypeWellKnownGroup,
		SidTypeDeletedAccount,
		SidTypeInvalid,
		SidTypeUnknown,
		SidTypeComputer
	}

	[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
	static extern bool LookupAccountSid(string lpSystemName, [MarshalAs(UnmanagedType.LPArray)] byte[] Sid, StringBuilder lpName, ref uint cchName, StringBuilder ReferencedDomainName, ref uint cchReferencedDomainName, out SID_NAME_USE peUse);


	private static String GetUsernameFromSID(string strSid)
	{
		StringBuilder name = new StringBuilder();
		uint cchName = (uint)name.Capacity;
		StringBuilder referencedDomainName = new StringBuilder();
		uint cchReferencedDomainName = (uint)referencedDomainName.Capacity;
		SID_NAME_USE sidUse;

		var sid = new SecurityIdentifier(strSid);
		byte[] byteSid = new byte[sid.BinaryLength];
		sid.GetBinaryForm(byteSid, 0);

		int err = (int)Win32Err.NO_ERROR;
		if (!LookupAccountSid(null, byteSid, name, ref cchName, referencedDomainName, ref cchReferencedDomainName, out sidUse))
		{
			err = Marshal.GetLastWin32Error();
			if (err == (int)Win32Err.ERROR_INSUFFICIENT_BUFFER)
			{
				name.EnsureCapacity((int)cchName);
				referencedDomainName.EnsureCapacity((int)cchReferencedDomainName);
				err = (int)Win32Err.NO_ERROR;
				if (!LookupAccountSid(null, byteSid, name, ref cchName, referencedDomainName, ref cchReferencedDomainName, out sidUse))
					err = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
			}
		}

		if (err != 0)
			throw new Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error().ToString());
		return String.Format("{0}{1}{2}", referencedDomainName.ToString(), (referencedDomainName.Length > 0 ? "\\" : ""), name.ToString());
	}

	public enum RSOPRetrieveType
	{
		Computer = 0x00000001,      //FLAG_NO_USER       = 0x00000001
		User = 0x00000002           //FLAG_NO_COMPUTER   = 0x00000002
	}

	public static Dictionary<String, String> GetRSOPGroups(RSOPRetrieveType retrvtype, SecurityIdentifier userSid = null)
	{
		Dictionary<String, String> ret = null;

		ManagementBaseObject inputArgs = null;
		ManagementBaseObject outParams = null;
		String namespc = string.Empty;

		if (userSid == null) userSid = WindowsIdentity.GetCurrent().User;

		using (ManagementClass mc = new ManagementClass(new ManagementPath("root\\rsop:RsopLoggingModeProvider"), new ObjectGetOptions(null, System.TimeSpan.MaxValue, true)))
		{
			inputArgs = mc.GetMethodParameters("RsopCreateSession");
			inputArgs["flags"] = retrvtype; 
			inputArgs["UserSid"] = userSid;
			outParams = mc.InvokeMethod("RsopCreateSession", inputArgs, null);
			//Console.WriteLine("RsopCreateSession() Result: {0}", outParams.Properties["hResult"].Value);
			try
			{
				if (((uint)outParams.Properties["hResult"].Value) == 0)
				{

					namespc = outParams.Properties["nameSpace"].Value as String;

					String wminamespace = String.Format("{0}\\{1}", namespc, retrvtype == RSOPRetrieveType.Computer ? "Computer" : "User");

					using (ManagementObjectCollection rsop_sessions = new ManagementObjectSearcher(wminamespace, "SELECT * FROM RSOP_Session").Get())
					{
						foreach (ManagementObject rsop_session in rsop_sessions)
						{
							if (ret == null) ret = new Dictionary<String, String>(StringComparer.InvariantCultureIgnoreCase);

							foreach (PropertyData prop in rsop_session.Properties)
							{
								if (prop.Value is String[])
								{
									//Console.WriteLine(prop.Name);
									String[] values = prop.Value as String[];
									foreach (String val in values)
									{
										//Console.WriteLine("{0} ({1})", GetUsernameFromSID(val), val);
										ret.Add(GetUsernameFromSID(val), val);
									}
								}
								//else
								//    Console.WriteLine("{0} = {1}", prop.Name, prop.Value is String[] ? String.Join(", ", prop.Value as String[]) : prop.Value);
							}

						}
					}
				}
			}
			catch (Exception) { }
			finally
			{
				if(!String.IsNullOrEmpty(namespc))
				{
					outParams = null;
					inputArgs = mc.GetMethodParameters("RsopDeleteSession");
					inputArgs["nameSpace"] = namespc;

					outParams = mc.InvokeMethod("RsopDeleteSession", inputArgs, null);
					//Console.WriteLine("RsopDeleteSession() Result: {0}", outParams.Properties["hResult"].Value);
				}
			}
		}

		return ret;
	}
}
"@ -ReferencedAssemblies "System.Management.dll"
	}

	process
	{
		$groups = $null

		if($User -eq $true)
		{
			$groups = [RSOPGroups]::GetRSOPGroups([RSOPGroups+RSOPRetrieveType]::User, $UserSID)
		}
		else
		{
			$groups = [RSOPGroups]::GetRSOPGroups([RSOPGroups+RSOPRetrieveType]::Computer)
		}
		
		
		if($groups -eq $null)
		{
			$null
		}
		else
		{
			$ret = [System.Collections.Hashtable]::new($groups)
		}
	}
}




