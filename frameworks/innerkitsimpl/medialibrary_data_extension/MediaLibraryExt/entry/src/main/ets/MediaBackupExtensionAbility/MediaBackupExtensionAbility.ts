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

const backupPath = '/data/storage/el2/backup/restore/';
const backupClonePath = '/data/storage/el2/backup/restore/storage/media/local/files/';
const documentPath = '/storage/media/local/files/Docs/Documents';
const galleryAppName = 'com.huawei.photos';
const mediaAppName = 'com.android.providers.media.module';

const UPGRADE_RESTORE : number = 0;
const DUAL_FRAME_CLONE_RESTORE : number = 1;
const CLONE_RESTORE : number = 2;

const UPGRADE_NAME = '0.0.0.0';
const DUAL_FRAME_CLONE_NAME = '99.99.99.999';

export default class MediaBackupExtAbility extends BackupExtensionAbility {
  async onBackup() : Promise<void> {
    console.log(TAG, 'onBackup ok.');
  }

  async onRestore(bundleVersion : BundleVersion) : Promise<void> {
    console.log(TAG, `onRestore ok ${JSON.stringify(bundleVersion)}`);
    console.time(TAG + ' RESTORE');
    let path:string;
    if (bundleVersion.name === UPGRADE_NAME && bundleVersion.code === 0) {
      await mediabackup.startRestore(UPGRADE_RESTORE, galleryAppName, mediaAppName);
      path = backupPath;
    } else if (bundleVersion.name === DUAL_FRAME_CLONE_NAME && bundleVersion.code === 0) {
      await mediabackup.startRestore(DUAL_FRAME_CLONE_RESTORE, galleryAppName, mediaAppName);
      path = backupPath;
    } else {
      await mediabackup.startRestore(CLONE_RESTORE, galleryAppName, mediaAppName);
      path = backupClonePath;
    }
    console.timeEnd(TAG + ' RESTORE');
    console.time(TAG + ' MOVE REST FILES');
    await this.moveRestFiles(path);
    console.timeEnd(TAG + ' MOVE REST FILES');
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
