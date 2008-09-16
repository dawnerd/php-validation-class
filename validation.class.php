<?php
/*
 |-------------------------------------------------------
 | Validation Class, written by Troy Whiteley: 2008
 | Version: 1.0
 |-------------------------------------------------------
 |
 | License:
 | The following code is licensed under the Buy Me Dew
 | license. Essentially you can use this code however
 | you want, all I ask if that you buy me some
 | Mountain Dew. I see it as a fair trade off:
 | I work a few hours and give you a free script
 | and you give me some caffeine so I can make more
 | free scripts. Oh, and you have to keep this little
 | blob of text so others know to buy me some Dew.
 | http://dawnerd.com/license/
 |
 |-------------------------------------------------------- 
 |
 | Provides a simple way to perform validation on
 | POST and GET variables. Can verify many data formats
 | and prevent against XSS attacks.
 |
 |--------------------------------------------------------
*/

class Validation
{
	private $RAW_POST;
	private $RAW_GET;
	private $COMBINED_DATA;
	
	public $SKIPPED_VARS = array();
	
	public function __construct($xss=true)
	{
		if(!is_array($_POST)) $_POST = array();
		if(!is_array($_GET)) $_GET = array();
		
		$this->RAW_POST = $_POST;
		$this->RAW_GET = $_GET;
		$this->COMBINED_DATA = array_merge($this->RAW_POST,$this->RAW_GET);
		
		$protected_vars = get_class_vars("Validation");
		foreach($this->COMBINED_DATA as $key => $value)
		{
			if(in_array(strtoupper($key),$protected_vars))
			{
				$this->SKIPPED_VARS[$key] = $value;
				continue;
			}
			$this->{$key} = $value;
			if($xss) $this->{$key} = $this->xss($value);
		}
	}
	
	/*
	 |----------------------------------------------------
	 | public function xss($val)
	 |----------------------------------------------------
	 |
	 | Parses $val and moves anything that could cause
	 | bad output to be displayed.
	 |
	 | returns sanitized $val
	 |
	 |----------------------------------------------------
	*/
	public function xss($val) 
	{
		//axe all non printables
		$val = preg_replace('/([\x00-\x08,\x0b-\x0c,\x0e-\x19])/', '', $val);
		
		$search = 'abcdefghijklmnopqrstuvwxyz';
		$search .= 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
		$search .= '1234567890!@#$%^&*()';
		$search .= '~`";:?+/={}[]-_|\'\\';
		for($i = 0; $i < strlen($search); $i++) 
		{
			//axe all non characters
			$val = preg_replace('/(&#[xX]0{0,8}'.dechex(ord($search[$i])).';?)/i', $search[$i], $val);
			$val = preg_replace('/(&#0{0,8}'.ord($search[$i]).';?)/', $search[$i], $val);
		}
	   
		$ra1 = array(
			'javascript','vbscript','expression',
			'applet','meta','xml','blink','link',
			'style','script','embed','object',
			'iframe','frame','frameset','ilayer',
			'layer','bgsound','title','base');
		$ra2 = array(
			'onabort','onactivate','onafterprint',
			'onafterupdate','onbeforeactivate',
			'onbeforecopy','onbeforecut',
			'onbeforedeactivate','onbeforeeditfocus',
			'onbeforepaste','onbeforeprint',
			'onbeforeunload','onbeforeupdate','onblur',
			'onbounce','oncellchange','onchange','onclick',
			'oncontextmenu','oncontrolselect','oncopy',
			'oncut','ondataavailable','ondatasetchanged',
			'ondatasetcomplete','ondblclick','ondeactivate',
			'ondrag','ondragend','ondragenter',
			'ondragleave','ondragover','ondragstart',
			'ondrop','onerror','onerrorupdate',
			'onfilterchange','onfinish','onfocus',
			'onfocusin','onfocusout','onhelp','onkeydown',
			'onkeypress','onkeyup','onlayoutcomplete',
			'onload','onlosecapture','onmousedown',
			'onmouseenter','onmouseleave','onmousemove',
			'onmouseout','onmouseover','onmouseup',
			'onmousewheel','onmove','onmoveend','onmovestart',
			'onpaste','onpropertychange','onreadystatechange',
			'onreset','onresize','onresizeend','onresizestart',
			'onrowenter','onrowexit','onrowsdelete',
			'onrowsinserted','onscroll','onselect',
			'onselectionchange','onselectstart','onstart',
			'onstop','onsubmit','onunload');
		$ra = array_merge($ra1, $ra2);
	   
		$found = true;
		while($found == true)
		{
			$val_before = $val;
			for($i = 0; $i < sizeof($ra); $i++) 
			{
				$pattern = '/';
				for($j = 0; $j < strlen($ra[$i]); $j++) 
				{
					if($j > 0) 
					{
						$pattern .= '((&#[xX]0{0,8}([9ab]);)||(&#0{0,8}([9|10|13]);))*';
					}
					$pattern .= $ra[$i][$j];
				}
				
				$pattern .= '/i';
				//break all on*
				$replacement = substr($ra[$i], 0, 2).'<x>'.substr($ra[$i], 2);
				$val = preg_replace($pattern, $replacement, $val);
				if($val_before == $val) $found = false;
			}
		}
	   return $val;
	}
	
	/*
	 |----------------------------------------------------
	 | public function email($val)
	 |----------------------------------------------------
	 |
	 | Parses $val and checks if it is a valid email.
	 |
	 | returns bool true| false
	 |
	 |----------------------------------------------------
	*/
	public function email($val)
	{
		$ereg = "^([a-zA-Z0-9_\-\.])+@(([0-2]?[0-5]?[0-5]\.[0-2]?[0-5]?[0-5]\.[0-2]?[0-5]?[0-5]\.[0-2]?[0-5]?[0-5])|((([a-zA-Z0-9\-])+\.)+([a-zA-Z\-])+))$";
		if(!eregi($ereg,$val))
		{
			return false;
		}
		
		list($user,$domain) = split("@",$val);
		
		if(getmxrr($domain,$mxhosts))
		{
			return true;
		}
		else
		{
			if(@fsockopen($domain,25,$error,$errorstr,30))
			{
				return true;
			}
			else
			{
				return false;
			}
		}
	}
	
	/*
	 |----------------------------------------------------
	 | public function phone($val)
	 |----------------------------------------------------
	 |
	 | Parses $val and checks if it is a valid 
	 | phone number.
	 |
	 | returns bool true| false
	 |
	 |----------------------------------------------------
	*/
	public function phone($val)
	{
		$ereg = "/^(?:\([2-9]\d{2}\)\ ?|[2-9]\d{2}[- \.]?)[2-9]\d{2}[- \.]?\d{4}[- \.]?(?:x|ext)?\.?\ ?\d{0,5}$/";
		if(!preg_match($ereg,$val))
		{
			return false;
		}
		return true;
	}
	
	/*
	 |----------------------------------------------------
	 | public function url($val)
	 |----------------------------------------------------
	 |
	 | Parses $val and checks if it is a valid url
	 |
	 | returns bool true| false
	 |
	 |----------------------------------------------------
	*/
	public function url($val)
	{
		$ereg = "((https?|ftp|gopher|telnet|file|notes|ms-help):((//)|(\\\\))+[\w\d:#@%/;$()~_?\+-=\\\.&]*)";
		if(!eregi($ereg,$val))
		{
			return false;
		}
		return true;
	}
	
	/*
	 |----------------------------------------------------
	 | public function db_prep($val)
	 |----------------------------------------------------
	 |
	 | Parses $val and prepares it for database input
	 |
	 | returns database ready $val
	 |
	 |----------------------------------------------------
	*/
	public function db_prep($val)
	{
		if(get_magic_quotes_gpc()) $val = stripslashes($val);
		return mysql_real_escape_string($val);
	}
}
?>