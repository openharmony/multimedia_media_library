/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import BackupExtensionAbility, {BundleVersion} from '@ohos.application.BackupExtensionAbility';
import fs from '@ohos.file.fs';
// @ts-ignore
import mediabackup from '@ohos.multimedia.mediabackup';

const TAG = 'MediaBackupExtAbility';

const documentPath = '/storage/media/local/files/Docs/Documents';
const galleryAppName = 'com.huawei.photos';
const mediaAppName = 'com.android.providers.media.module';

const UPGRADE_RESTORE : number = 0;
const DUAL_FRAME_CLONE_RESTORE : number = 1;
const CLONE_RESTORE : number = 2;

const UPGRADE_NAME = '0.0.0.0';
const DUAL_FRAME_CLONE_NAME = '99.99.99.999';
const STAT_KEY_RESULT_INFO = 'resultInfo';
const STAT_KEY_TYPE = 'type';
const STAT_KEY_ERROR_CODE = 'errorCode';
const STAT_KEY_ERROR_INFO = 'errorInfo';
const STAT_KEY_INFOS = 'infos';
const STAT_KEY_BACKUP_INFO = 'backupInfo';
const STAT_KEY_SUCCESS_COUNT = 'successCount';
const STAT_KEY_DUPLICATE_COUNT = 'duplicateCount';
const STAT_KEY_FAILED_COUNT = 'failedCount';
const STAT_KEY_DETAILS = 'details';
const STAT_KEY_NUMBER = 'number';
const STAT_VALUE_ERROR_INFO = 'ErrorInfo';
const STAT_VALUE_COUNT_INFO = 'CountInfo';
const STAT_TYPE_PHOTO = 'photo';
const STAT_TYPE_VIDEO = 'video';
const STAT_TYPE_AUDIO = 'audio';
const STAT_TYPES = [STAT_TYPE_PHOTO, STAT_TYPE_VIDEO, STAT_TYPE_AUDIO];
const RESULT_INFO_NUM = 2;
const JS_TYPE_STRING = 'string';
const DEFAULT_RESTORE_EX_INFO = {
  'resultInfo':
  [
    {
      'type': STAT_VALUE_ERROR_INFO,
      'errorCode': '13500099',
      'errorInfo': 'Get restoreEx info failed'
    },
    {
      'type': STAT_VALUE_COUNT_INFO,
      'infos':
      [
        {
          'backupInfo': STAT_TYPE_PHOTO,
          'successCount': 0,
          'duplicateCount': 0,
          'failedCount': 0,
          'details': null
        },
        {
          'backupInfo': STAT_TYPE_VIDEO,
          'successCount': 0,
          'duplicateCount': 0,
          'failedCount': 0,
          'details': null
        },
        {
          'backupInfo': STAT_TYPE_AUDIO,
          'successCount': 0,
          'duplicateCount': 0,
          'failedCount': 0,
          'details': null
        }
      ]
    }
  ]
};
const DEFAULT_BACKUP_INFO = [
  {
    'backupInfo': STAT_TYPE_PHOTO,
    'number': 0
  },
  {
    'backupInfo': STAT_TYPE_VIDEO,
    'number': 0
  },
  {
    'backupInfo': STAT_TYPE_AUDIO,
    'number': 0
  }
];

export default class MediaBackupExtAbility extends BackupExtensionAbility {
  async onBackup() : Promise<void> {
    console.log(TAG, 'onBackup ok.');
  }

  async onRestore(bundleVersion : BundleVersion) : Promise<void> {
    console.log(TAG, `onRestore ok ${JSON.stringify(bundleVersion)}`);
    console.time(TAG + ' RESTORE');
    const backupDir = this.context.backupDir + 'restore';
    let path:string;
    if (bundleVersion.name.startsWith(UPGRADE_NAME)) {
      await mediabackup.startRestore(UPGRADE_RESTORE, galleryAppName, mediaAppName, backupDir);
      path = backupDir;
    } else if (bundleVersion.name === DUAL_FRAME_CLONE_NAME && bundleVersion.code === 0) {
      await mediabackup.startRestore(DUAL_FRAME_CLONE_RESTORE, galleryAppName, mediaAppName, backupDir);
      path = backupDir;
    } else {
      await mediabackup.startRestore(CLONE_RESTORE, galleryAppName, mediaAppName, backupDir);
      path = backupDir + '/storage/media/local/files/';
    }
    console.timeEnd(TAG + ' RESTORE');
    console.time(TAG + ' MOVE REST FILES');
    await this.moveRestFiles(path);
    console.timeEnd(TAG + ' MOVE REST FILES');
  }

  async onRestoreEx(bundleVersion: BundleVersion, bundleInfo: string): Promise<string> {
    console.log(TAG, `onRestoreEx ok ${JSON.stringify(bundleVersion)}, ${bundleInfo}`);
    console.time(TAG + ' RESTORE EX');
    const backupDir = this.context.backupDir + 'restore';
    let restoreExResult: string;
    let path: string;
    if (bundleVersion.name.startsWith(UPGRADE_NAME)) {
      restoreExResult = await mediabackup.startRestore(UPGRADE_RESTORE, galleryAppName, mediaAppName, backupDir);
      path = backupDir;
    } else if (bundleVersion.name === DUAL_FRAME_CLONE_NAME && bundleVersion.code === 0) {
      restoreExResult = await mediabackup.startRestore(DUAL_FRAME_CLONE_RESTORE, galleryAppName, mediaAppName, backupDir);
      path = backupDir;
    } else {
      restoreExResult = await mediabackup.startRestore(CLONE_RESTORE, galleryAppName, mediaAppName, backupDir);
      path = backupDir + '/storage/media/local/files/';
    }
    let restoreExInfo: string = await this.getRestoreExInfo(restoreExResult);
    console.log(TAG, `GET restoreExInfo: ${restoreExInfo}`);
    console.timeEnd(TAG + ' RESTORE EX');
    console.time(TAG + ' MOVE REST FILES');
    await this.moveRestFiles(path);
    console.timeEnd(TAG + ' MOVE REST FILES');
    return restoreExInfo;
  }

  getBackupInfo(): string {
    console.log(TAG, 'getBackupInfo ok');
    let tmpBackupInfo: string = mediabackup.getBackupInfo(CLONE_RESTORE);
    let backupInfo: string;
    if (!this.isBackupInfoValid(tmpBackupInfo)) {
      console.error(TAG, 'backupInfo is invalid, return default');
      backupInfo = JSON.stringify(DEFAULT_BACKUP_INFO);
    } else {
      backupInfo = tmpBackupInfo;
    }
    console.log(TAG, `GET backupInfo: ${backupInfo}`);
    return backupInfo;
  }

  private async getRestoreExInfo(restoreExResult: string): Promise<string> {
    if (!this.isRestoreExResultValid(restoreExResult)) {
      console.error(TAG, 'restoreEx result is invalid, use default');
      return JSON.stringify(DEFAULT_RESTORE_EX_INFO);
    }
    try {
      let jsonObject = JSON.parse(restoreExResult);
      for (let info of jsonObject.resultInfo) {
        if (info.type !== STAT_VALUE_COUNT_INFO) {
          continue;
        }
        for (let subCountInfo of info.infos) {
          let type = subCountInfo.backupInfo;
          let detailsPath = subCountInfo.details;
          subCountInfo.details = await this.getDetails(type, detailsPath);
        }
      }
      return JSON.stringify(jsonObject);
    } catch (err) {
      console.error(TAG, `getRestoreExInfo error message: ${err.message}, code: ${err.code}`);
      return JSON.stringify(DEFAULT_RESTORE_EX_INFO);
    }
  }

  private async getDetails(type: string, detailsPath: string): Promise<null | number> {
    if (detailsPath.length === 0) {
      console.log(TAG, `${type} has no failed files`);
      return null;
    }
    let file = await fs.open(detailsPath);
    console.log(TAG, `${type} details path: ${detailsPath}, fd: ${file.fd}`);
    return file.fd;
  }

  private isRestoreExResultValid(restoreExResult: string): boolean {
    try {
      let jsonObject = JSON.parse(restoreExResult);
      if (!this.hasKey(jsonObject, STAT_KEY_RESULT_INFO)) {
        return false;
      }
      let resultInfo = jsonObject[STAT_KEY_RESULT_INFO];
      if (resultInfo.length !== RESULT_INFO_NUM) {
        console.error(TAG, `resultInfo num ${resultInfo.length} != ${RESULT_INFO_NUM}`);
        return false;
      }
      let errorInfo = resultInfo[0];
      let countInfo = resultInfo[1];
      return this.isErrorInfoValid(errorInfo) && this.isCountInfoValid(countInfo);
    } catch (err) {
      console.error(TAG, `isRestoreExResultValid error message: ${err.message}, code: ${err.code}`);
      return false;
    }
  }

  private isErrorInfoValid(errorInfo: JSON): boolean {
    if (!this.hasKey(errorInfo, STAT_KEY_TYPE) || !this.hasKey(errorInfo, STAT_KEY_ERROR_CODE) ||
      !this.hasKey(errorInfo, STAT_KEY_ERROR_INFO)) {
      return false;
    }
    if (errorInfo[STAT_KEY_TYPE] !== STAT_VALUE_ERROR_INFO) {
      console.error(TAG, `errorInfo ${errorInfo[STAT_KEY_TYPE]} != ${STAT_VALUE_ERROR_INFO}`);
      return false;
    }
    if (!this.checkType(typeof errorInfo[STAT_KEY_ERROR_CODE], JS_TYPE_STRING) ||
      !this.checkType(typeof errorInfo[STAT_KEY_ERROR_INFO], JS_TYPE_STRING)) {
      return false;
    }
    return true;
  }

  private isCountInfoValid(countInfo: JSON): boolean {
    if (!this.hasKey(countInfo, STAT_KEY_TYPE) || !this.hasKey(countInfo, STAT_KEY_INFOS)) {
      return false;
    }
    if (countInfo[STAT_KEY_TYPE] !== STAT_VALUE_COUNT_INFO) {
      console.error(TAG, `countInfo ${countInfo[STAT_KEY_TYPE]} != ${STAT_VALUE_COUNT_INFO}`);
      return false;
    }
    let subCountInfos = countInfo[STAT_KEY_INFOS];
    if (subCountInfos.length !== STAT_TYPES.length) {
      console.error(TAG, `countInfo ${subCountInfos.length} != ${STAT_TYPES.length}`);
      return false;
    }
    let hasPhoto = false;
    let hasVideo = false;
    let hasAudio = false;
    for (let subCountInfo of subCountInfos) {
      if (!this.isSubCountInfoValid(subCountInfo)) {
        return false;
      }
      hasPhoto = hasPhoto || subCountInfo[STAT_KEY_BACKUP_INFO] === STAT_TYPE_PHOTO;
      hasVideo = hasVideo || subCountInfo[STAT_KEY_BACKUP_INFO] === STAT_TYPE_VIDEO;
      hasAudio = hasAudio || subCountInfo[STAT_KEY_BACKUP_INFO] === STAT_TYPE_AUDIO;
    }
    return hasPhoto && hasVideo && hasAudio;
  }

  private isSubCountInfoValid(subCountInfo: JSON): boolean {
    if (!this.hasKey(subCountInfo, STAT_KEY_BACKUP_INFO) || !this.hasKey(subCountInfo, STAT_KEY_SUCCESS_COUNT) ||
      !this.hasKey(subCountInfo, STAT_KEY_DUPLICATE_COUNT) || !this.hasKey(subCountInfo, STAT_KEY_FAILED_COUNT) ||
      !this.hasKey(subCountInfo, STAT_KEY_DETAILS)) {
      return false;
    }
    if (!STAT_TYPES.includes(subCountInfo[STAT_KEY_BACKUP_INFO])) {
      console.error(TAG, `SubCountInfo ${subCountInfo[STAT_KEY_BACKUP_INFO]} not in ${JSON.stringify(STAT_TYPES)}`);
      return false;
    }
    return !isNaN(subCountInfo[STAT_KEY_SUCCESS_COUNT]) && !isNaN(subCountInfo[STAT_KEY_DUPLICATE_COUNT]) &&
      !isNaN(subCountInfo[STAT_KEY_FAILED_COUNT]) ;
  }

  private isBackupInfoValid(backupInfo: string): boolean {
    try {
      let jsonObject = JSON.parse(backupInfo);
      if (jsonObject.length !== STAT_TYPES.length) {
        console.error(TAG, `backupInfo num ${jsonObject.length} != ${STAT_TYPES.length}`);
        return false;
      }
      let hasPhoto = false;
      let hasVideo = false;
      let hasAudio = false;
      for (let subBackupInfo of jsonObject) {
        if (!this.isSubBackupInfoValid(subBackupInfo)) {
          return false;
        }
        hasPhoto = hasPhoto || subBackupInfo[STAT_KEY_BACKUP_INFO] === STAT_TYPE_PHOTO;
        hasVideo = hasVideo || subBackupInfo[STAT_KEY_BACKUP_INFO] === STAT_TYPE_VIDEO;
        hasAudio = hasAudio || subBackupInfo[STAT_KEY_BACKUP_INFO] === STAT_TYPE_AUDIO;
      }
      return hasPhoto && hasVideo && hasAudio;
    } catch (err) {
      console.error(TAG, `isBackupInfoValid error message: ${err.message}, code: ${err.code}`);
      return false;
    }
  }

  private isSubBackupInfoValid(subBackupInfo: JSON): boolean {
    if (!this.hasKey(subBackupInfo, STAT_KEY_BACKUP_INFO) || !this.hasKey(subBackupInfo, STAT_KEY_NUMBER)) {
      return false;
    }
    if (!STAT_TYPES.includes(subBackupInfo[STAT_KEY_BACKUP_INFO])) {
      console.error(TAG, `SubBackupInfo ${subBackupInfo[STAT_KEY_BACKUP_INFO]} not in ${JSON.stringify(STAT_TYPES)}`);
      return false;
    }
    return !isNaN(subBackupInfo[STAT_KEY_NUMBER]);
  }

  private hasKey(jsonObject: JSON, key: string): boolean {
    if (!(key in jsonObject)) {
      console.error(TAG, `hasKey ${key} not found`);
      return false;
    }
    return true;
  }

  private checkType(varType: string, expectedType: string): boolean {
    if (varType !== expectedType) {
      console.error(TAG, `checkType ${varType} != ${expectedType}`);
      return false;
    }
    return true;
  }

  private isFileExist(filePath : string) : boolean {
    try {
      return fs.accessSync(filePath);
    } catch (err) {
      console.error(TAG, `accessSync failed, message = ${err.message}; code = ${err.code}`);
      return false;
    }
  }

  private async moveRestFiles(path : string) : Promise<void> {
    console.log(TAG, 'Start to move rest files.');
    const MOVE_ERR_CODE = 13900015;
    let list = [];
    try {
      await fs.moveDir(path, documentPath, 1);
      console.info(TAG, 'Move rest files succeed');
    } catch (err) {
      if (err.code === MOVE_ERR_CODE) {
        list = err.data;
      } else {
        console.error(TAG, `move directory failed, message = ${err.message}; code = ${err.code}`);
      }
    }

    for (let i = 0; i < list.length; i++) {
      try {
        await this.moveConflictFile(list[i].srcFile, list[i].destFile);
      } catch (err) {
        console.error(TAG, `MoveConflictFile failed, message = ${err.message}; code = ${err.code}`);
      }
    }
  }

  private async moveConflictFile(srcFile : string, dstFile : string) : Promise<void> {
    const srcArr = srcFile.split('/');
    const dstArr = dstFile.split('/');
    const srcFileName = srcArr[srcArr.length - 1];
    const dirPath = dstArr.splice(0, dstArr.length - 1).join('/');
    let fileExt : string = '';
    let fileNameWithoutExt = srcFileName;
    if (srcFileName.lastIndexOf('.') !== -1) {
      let tmpValue = srcFileName.split('.').pop();
      if (tmpValue !== undefined) {
        fileExt = tmpValue;
        fileNameWithoutExt = srcFileName.slice(0, srcFileName.length - fileExt.length - 1);
      }
    }
    let newFileName = srcFileName;
    let count = 1;
    while (this.isFileExist(`${dirPath}/${newFileName}`)) {
      if (fileExt === '') {
        newFileName = `${fileNameWithoutExt}(${count})`;
      } else {
        newFileName = `${fileNameWithoutExt}(${count}).${fileExt}`;
      }
      count++;
    }
    try {
      await fs.moveFile(srcFile, `${dirPath}/${newFileName}`);
    } catch (err) {
      console.error(TAG, `moveFile file failed, message = ${err.message}; code = ${err.code}`);
    }
  }
}
