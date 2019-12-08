<?php
/**
 * @package     zero-24.antispam.userprofile
 * @copyright   Copyright (C) 2019 Tobias Zulauf (https://forum.joomla.de). All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */
namespace wcf\system\event\listener;

use wcf\data\user\User;
use wcf\data\user\UserAction;
use wcf\system\event\listener\IParameterizedEventListener;
use wcf\system\WCF;
use wcf\util\StringUtil;

/**
 * Anti Spam Userprofile User Listener
 *
 * @since  1.0.0
 */
class AntiSpamUserActionListener implements IParameterizedEventListener
{
	/**
	 * Whitelisted chars that should be excluded from the checks
	 *
	 * @var     array
	 * @since   1.0.0
	 */
	private $globalWitelistedChars = [
		'ß',
		'ä',
		'ü',
		'ö',
		'´',
		'€',
		'°',
		'“',
		'„',
		'–',
	];

	/**
	 * Make sure we only run our checks once
	 *
	 * @var     array
	 * @since   1.0.0
	 */
	private $objectsChecked = [];

	/**
	 * The Event Listener execute method that handles the checks
	 *
	 * @param   object   $eventObj    The event object
	 * @param   string   $className   The classname
	 * @param   string   $eventName   The event name
	 * @param   array    $parameters  The event parameters array
	 *
	 * @return  void
	 *
	 * @see     \wcf\system\event\listener\IParameterizedEventListener::execute()
	 * @since   1.0.0
	 */
	public function execute($eventObj, $className, $eventName, array &$parameters)
	{
		$actionName = $eventObj->getActionName();
		$parameters = $eventObj->getParameters();

		if (in_array($actionName, ['create', 'update']))
		{
			// Make sure we have the options parameter
			if (!isset($parameters['options']))
			{
				return;
			}

			foreach ($eventObj->getObjects() as $object)
			{
				$objectId = $object->getObjectID();

				// Early exit in the case that we already checked this item
				if (isset($this->objectsChecked[$objectId]) && $this->objectsChecked[$objectId])
				{
					continue;
				}

				// Mark this objectId as checked
				$this->objectsChecked[$objectId] = true;

				// Make sure the execution is not disabled
				if (!USER_ANTISPAMUSERPROFILE_ENABLE
					|| WCF::getSession()->getPermission('user.board.canBypassAntiSpamUserprofile'))
				{
					continue;
				}

				// The default value is false
				$foundNotAllowedChar = false;
				$newOptions = [];

				foreach ($parameters['options'] as $option => $value)
				{
					if ($this->checkContent($value) === true)
					{
						// We found not allowed content here..
						$newOptions[$option] = '';
						// ... we make that field empty now
						$foundNotAllowedChar = true;
						// ... and note that we found something
					}
				}

				// We have found nothing -> exit
				if ($foundNotAllowedChar === false)
				{
					continue;
				}

				switch (USER_ANTISPAMUSERPROFILE_ACTION)
				{
					// With the clean mode we just clean the values
					case 'clean':
						$object->updateUserOptions($newOptions);
						break;
					// With the ban mode we just ban but don't touch the actual content of the fields
					case 'ban':
						$userID = $object->getData()['userID'];
						$this->banUser($userID);
						break;
					// With the both case we do both. Clean the values and ban the user
					default:
					case 'both':
						$object->updateUserOptions($newOptions);
						$userID = $object->getData()['userID'];
						$this->banUser($userID);
						break;
				}
			}
		}
	}

	/**
	 * Trigger a UserAction to permanetly ban the passed UserID
	 *
	 * @param   string   $userID  The userID to ban
	 *
	 * @return  void
	 *
	 * @since   1.0.0
	 */
	private function banUser($userID): void
	{
			// Permanetly ban the user
			(new UserAction([(new User($userID))], 'ban', [
				'banExpires' => 0,
				'banReason'  => StringUtil::encodeHTML(USER_ANTISPAMUSERPROFILE_BANREASON),
			]))->executeAction();
	}

	/**
	 * Parses the content and return true whether the post should be blocked
	 *
	 * @param   string   $text  The text to be parsed
	 *
	 * @return  boolean  True whether the post should be blocked
	 *
	 * @since   1.0.0
	 */
	private function checkContent($text): bool
	{
		$customBlacklist  = explode(',', USER_ANTISPAMUSERPROFILE_BLACKLIST);
		$whitelistedChars = explode(',', USER_ANTISPAMUSERPROFILE_WHITELIST);
		$whitelistedChars = array_merge($whitelistedChars, $this->globalWitelistedChars);

		// Make sure the whitelisted chars does not trigger the checker
		foreach ($whitelistedChars as $whitelistedChar)
		{
			$text = str_replace($whitelistedChar, '', $text);

			$whitelistedChar = mb_strtoupper($whitelistedChar, 'UTF-8');
			$text = str_replace($whitelistedChar, '', $text);
		}

		$clearstring = filter_var($text, FILTER_UNSAFE_RAW, FILTER_FLAG_STRIP_HIGH);

		// Remove the blacklisted words / chars so that it triggers the checker
		foreach ($customBlacklist as $blacklisted)
		{
			$clearstring = str_replace($blacklisted, '', $clearstring);
		}

		if ($clearstring != $text)
		{
			return true;
		}

		return false;
	}
}
