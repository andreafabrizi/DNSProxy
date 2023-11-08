
var serverData = false;

if (window.XMLHttpRequest)
{
	serverData = new XMLHttpRequest();
}
else if (window.ActiveXObject)
{
	serverData = new ActiveXObject("Microsoft.XMLHTTP");
}

function dnsCheck(inputId,outputId)
{
	var outputElem = document.getElementById(outputId);
	var inputElem  = document.getElementById(inputId);
	var lookupResults;
	if (serverData)
	{
		serverData.open('GET','dns.php?domain=' + inputElem.value);
		serverData.onreadystatechange = function()
		{
			if (serverData.readyState == 4 && serverData.status == 200)
			{
				lookupResults = serverData.responseText;
				if (lookupResults == -150)
				{
					outputElem.innerHTML = "No Domain Given";
				}
				else if (lookupResults == -100)
				{
					outputElem.innerHTML = "Lookup Failed/Invalid Domain";
				}
				else
				{
					outputElem.innerHTML = "IP: <p>" + lookupResults + ". ";
				}
			}
		}
		serverData.send(null);
	}
	else
	{
		outputElem.innerHTML = "Failed To Create XMLHttpRequest Object";
	}
}
