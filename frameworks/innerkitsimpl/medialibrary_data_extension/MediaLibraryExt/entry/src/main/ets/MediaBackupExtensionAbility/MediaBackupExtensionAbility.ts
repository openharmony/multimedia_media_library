import BackupExtensionAbility, {BundleVersion} from '@ohos.application.BackupExtensionAbility';
import fs from '@ohos.file.fs';
import relationalStore from '@ohos.data.relationalStore';
// @ts-ignore
import mediabackup from '@ohos.multimedia.mediabackup';

const TAG = 'MediaBackupExtAbility';
const originPath = '/data/storage/el2/base/backup/restore';
const clonePath = '/data/storage/el2/backup/restore';
const updaterPath = '/storage/media/local/files/android';
const documentPath = '/storage/media/local/files/Documents';
const srcGalleryPath = '/com.huawei.photos/ce/databases/';
const srcMediaPath = clonePath + '/data/storage/el2/database/rdb/';
const cloneTag = '/cloneBackupData.json';
const PREFIX_LEVEL = 4;
const RESTORE_NUMBER = 500;
const MILLISE_SECOND = 1000;
let backupConext = undefined;
const galleryDbConfig = {
  name: 'gallery.db',
  securityLevel: relationalStore.SecurityLevel.S1
};
const mediaDbConfig = {
  name: 'media_library.db',
  securityLevel: relationalStore.SecurityLevel.S2
};

interface FileInfo {
  filePath : string;
  displayName : string;
  _size : number;
  duration : number;
  recycledTime : number;
  hidden : number;
  isFavorite : number;
  fileType : number;
  showDateToken : number;
  height : number;
  width : number;
};

export default class MediaBackupExtAbility extends BackupExtensionAbility {
  async onBackup() : Promise<void> {
    console.log(TAG, 'onBackup ok.');
  }

  async onRestore(bundleVersion : BundleVersion) : Promise<void> {
    console.log(TAG, `onRestore ok ${JSON.stringify(bundleVersion)}`);
    // @ts-ignore
    backupConext = this.context;
    if (bundleVersion.name === '0.0.0.0' && bundleVersion.code === 0) {
      await this.restoreMediaForDouble().catch(err => {
        console.error(TAG, `restoreMediaForDouble failed, message = ${err.message}; code = ${err.code}`);
      });
      await this.delAppData();
    } else {
      await this.restoreMediaForSingle().catch(err => {
        console.error(TAG, `restoreMediaForSingle failed, message = ${err.message}; code = ${err.code}`);
      });
    }
    await this.moveRestFiles();
  }

  private async restoreMediaForDouble() : Promise<void> {
    console.log(TAG, 'Step1: Get media file for updater or clone');
    await this.createRdb(galleryDbConfig);
    let dbFileName : string[] = ['gallery.db', 'gallery.db-wal', 'gallery.db-shm'];
    let dbPath = originPath + srcGalleryPath;
    let prefixPath = updaterPath;
    if (this.isFileExist(clonePath + cloneTag)) {
      dbPath = clonePath + srcGalleryPath;
      prefixPath = clonePath;
    }
    this.moveDbFiles(dbFileName, dbPath, backupConext.databaseDir + '/rdb/');
    await this.restoreMedia(prefixPath).catch(err => {
      console.error(TAG, `restoreMedia failed, message = ${err.message}; code = ${err.code}`);
    });
  }

  private async restoreMediaForSingle() : Promise<void> {
    console.log(TAG, 'Step1: Get media file for clone');
    await this.createRdb(mediaDbConfig);
    let dbFileName : string[] = ['media_library.db', 'media_library.db-wal', 'media_library.db-shm'];
    this.moveDbFiles(dbFileName, srcMediaPath, backupConext.databaseDir + '/rdb/');
    await this.restoreMediaDbForSingle().catch(err => {
      console.error(TAG, `restoreMediaDbForSingle failed, message = ${err.message}; code = ${err.code}`);
    });
  }

  private async createRdb(dbConfig : relationalStore.StoreConfig) : Promise<void> {
    console.log(TAG, 'Step1.1: Create Rdb');
    await relationalStore.getRdbStore(backupConext, dbConfig).catch(err => {
      console.error(TAG, `createRdb failed, message = ${err.message}; code = ${err.code}`);
    });
  }

  private async moveDbFiles(filesName : string[], srcPath : string, dstPath : string) : Promise<void> {
    console.info(TAG, 'Step1.2: Move db Files.');
    for (let i = 0; i < filesName.length; ++i) {
      let filePath = srcPath + filesName[i];
      try {
        if (fs.accessSync(filePath)) {
          fs.copyFileSync(filePath, dstPath + filesName[i], 0);
        } else {
          console.error(TAG, 'Db file is not exist');
        }
      } catch (err) {
        console.error(TAG, `Move db files failed, message = ${err.message}; code = ${err.code}`);
      }
    }
  }

  private async restoreMedia(prefixPath: string) : Promise<void> {
    console.log(TAG, 'Step1.3: start to restore media.');
    let rdbStore = await relationalStore.getRdbStore(backupConext, galleryDbConfig);
    let totalNumber = 0;
    let queryCount = `SELECT count(1) as count FROM gallery_media
      WHERE (local_media_id >= 0 OR local_media_id == -4) AND (storage_id = 65537) AND relative_bucket_id NOT IN (
      SELECT DISTINCT relative_bucket_id FROM garbage_album WHERE type = 1)`;
    let resultSet = await rdbStore.querySql(queryCount);
    while (resultSet.goToNextRow()) {
      totalNumber = resultSet.getLong(resultSet.getColumnIndex('count'));
    }
    resultSet.close();
    console.log(TAG, `QueryCount, totalNumber = ${totalNumber}`);
    for (let index = 0; index < totalNumber; index += RESTORE_NUMBER) {
      await this.batchRestoreFiles(index, rdbStore, prefixPath).catch(err => {
        console.error(TAG, `batchRestoreFiles failed, message = ${err.message}; code = ${err.code}`);
      });
    }
    if (!this.isFileExist(clonePath + cloneTag)) {
      mediabackup.moveFiles(updaterPath);
    }
    console.log(TAG, 'Finish restore media files, then move other files.');
  }

  private async restoreMediaDbForSingle() : Promise<void> {
    console.log(TAG, 'Step1.3: start to restore media_library.db.');
    let rdbStore = await relationalStore.getRdbStore(backupConext, mediaDbConfig);
    let totalNumber = 0;
    let queryCount = 'SELECT count(1) as count FROM Photos';
    let resultSet = await rdbStore.querySql(queryCount);
    while (resultSet.goToNextRow()) {
      totalNumber = resultSet.getLong(resultSet.getColumnIndex('count'));
    }
    resultSet.close();
    console.log(TAG, `QueryCount, totalNumber = ${totalNumber}`);
    for (let index = 0; index < totalNumber; index += RESTORE_NUMBER) {
      await this.batchRestoreFilesForSingle(index, rdbStore).catch(err => {
        console.error(TAG, `batchRestoreFilesForSingle failed, message = ${err.message}; code = ${err.code}`);
      });
    }
    console.log(TAG, 'Finish restore media_library files, then move other files.');
  }

  private async batchRestoreFiles(offset: number, rdbStore: relationalStore.RdbStore,
    prefixPath: string) : Promise<void> {
    let galleyFileList : FileInfo[] = [];
    try {
      let queryStatement = `SELECT local_media_id,_data,_display_name,is_hw_favorite,recycledTime,_size,duration,
        media_type,showDateToken,height,width FROM gallery_media WHERE (local_media_id >= 0 OR local_media_id == -4) AND
        (storage_id = 65537) AND relative_bucket_id NOT IN (
        SELECT DISTINCT relative_bucket_id FROM garbage_album WHERE type = 1
        ) ORDER BY showDateToken ASC limit ${offset} ,${RESTORE_NUMBER}`;
      let resultSet = await rdbStore.querySql(queryStatement);
      while (resultSet.goToNextRow()) {
        let tmpValue : FileInfo = this.parseResultSet(resultSet, prefixPath);
        galleyFileList.push(tmpValue);
      }
      mediabackup.startRestore(galleyFileList);
      resultSet.close();
    } catch (err) {
      console.error(TAG, `Try to restore media failed, message = ${err.message}; code = ${err.code}`);
    }
  }

  private async batchRestoreFilesForSingle(offset: number, rdbStore: relationalStore.RdbStore) : Promise<void> {
    let mediaLibraryFileList : FileInfo[] = [];
    try {
      let queryStatement = `SELECT data,display_name,size,duration,date_trashed,hidden,is_favorite,media_type,
        date_added,height,width FROM Photos limit ${offset} ,${RESTORE_NUMBER}`;
      let resultSet = await rdbStore.querySql(queryStatement);
      while (resultSet.goToNextRow()) {
        let tmpValue : FileInfo = this.parseResultSetForSingle(resultSet);
        mediaLibraryFileList.push(tmpValue);
      }
      mediabackup.startRestore(mediaLibraryFileList);
      resultSet.close();
    } catch (err) {
      console.error(TAG, `Try to restore media failed, message = ${err.message}; code = ${err.code}`);
    }
  }

  private parseResultSet(resultSet : relationalStore.ResultSet, prefixPath: string) : FileInfo {
    const HIDDEN_ID = -4;
    let fileParts = resultSet.getString(resultSet.getColumnIndex('_data')).split('/');
    let srcPath = fileParts.slice(PREFIX_LEVEL).join('/');
    let isHidden = 0;
    const mediaId = resultSet.getLong(resultSet.getColumnIndex('local_media_id'));
    if (mediaId === HIDDEN_ID) {
      isHidden = 1;
    }
    return {
      filePath: prefixPath + '/' + srcPath,
      displayName: resultSet.getString(resultSet.getColumnIndex('_display_name')),
      _size: resultSet.getLong(resultSet.getColumnIndex('_size')),
      duration: resultSet.getLong(resultSet.getColumnIndex('duration')),
      recycledTime: resultSet.getLong(resultSet.getColumnIndex('recycledTime')) / MILLISE_SECOND,
      hidden: isHidden,
      isFavorite: resultSet.getLong(resultSet.getColumnIndex('is_hw_favorite')),
      fileType: resultSet.getLong(resultSet.getColumnIndex('media_type')),
      showDateToken: resultSet.getLong(resultSet.getColumnIndex('showDateToken')) / MILLISE_SECOND,
      height: resultSet.getLong(resultSet.getColumnIndex('height')),
      width: resultSet.getLong(resultSet.getColumnIndex('width')),
    };
  }

  private parseResultSetForSingle(resultSet : relationalStore.ResultSet) : FileInfo {
    const OLD_VIDEO_TYPE = 3;
    const MEDIA_VIDEO_TYPE = 2;
    let fileParts = resultSet.getString(resultSet.getColumnIndex('data')).split('/');
    let srcPath = fileParts.slice(PREFIX_LEVEL).join('/');
    let mediaType = resultSet.getLong(resultSet.getColumnIndex('media_type'));
    if (mediaType === MEDIA_VIDEO_TYPE) {
      mediaType = OLD_VIDEO_TYPE;
    }
    return {
      filePath: clonePath + '/' + srcPath,
      displayName: resultSet.getString(resultSet.getColumnIndex('display_name')),
      _size: resultSet.getLong(resultSet.getColumnIndex('size')),
      duration: resultSet.getLong(resultSet.getColumnIndex('duration')),
      recycledTime: resultSet.getLong(resultSet.getColumnIndex('date_trashed')),
      hidden: resultSet.getLong(resultSet.getColumnIndex('hidden')),
      isFavorite: resultSet.getLong(resultSet.getColumnIndex('is_favorite')),
      fileType: mediaType,
      showDateToken: resultSet.getLong(resultSet.getColumnIndex('date_added')),
      height: resultSet.getLong(resultSet.getColumnIndex('height')),
      width: resultSet.getLong(resultSet.getColumnIndex('width')),
    };
  }

  private isFileExist(filePath : string) : boolean {
    try {
      return fs.accessSync(filePath);
    } catch (err) {
      console.error(TAG, `accessSync failed, message = ${err.message}; code = ${err.code}`);
      return false;
    }
  }

  private async delAppData() : Promise<void> {
    console.log(TAG, 'Step2: Del application data.');
    let prefixPath = originPath;
    if (this.isFileExist(clonePath + cloneTag)) {
      prefixPath = clonePath;
    }
    let photoPath = prefixPath + '/com.huawei.photos';
    let mediaPath = prefixPath + '/com.android.providers.media.module';
    await fs.rmdir(photoPath).catch(err => {
      console.error(TAG, `remove photoPath failed, message = ${err.message}; code = ${err.code}`);
    });
    await fs.rmdir(mediaPath).catch(err => {
      console.error(TAG, `remove mediaPath failed, message = ${err.message}; code = ${err.code}`);
    });
  }

  private async moveRestFiles() : Promise<void> {
    console.log(TAG, 'Step3: Move rest files.');
    if (!this.isFileExist(clonePath + cloneTag)) {
      return;
    }
    const MOVE_ERR_CODE = 13900015;
    await fs.moveDir(clonePath + '/', documentPath, 1).then(() => {
      console.info(TAG, 'Move rest files succeed');
    }).catch((err) => {
      if (err.code === MOVE_ERR_CODE) {
        for (let i = 0; i < err.data.length; i++) {
          this.moveConflictFile(err.data[i].srcFile, err.data[i].destFile).catch(err => {
            console.error(TAG, `MoveConflictFile failed, message = ${err.message}; code = ${err.code}`);
          });
        }
      } else {
        console.error(TAG, `move directory failed, message = ${err.message}; code = ${err.code}`);
      }
    });
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
    await fs.moveFile(srcFile, `${dirPath}/${newFileName}`).catch(err => {
      console.error(TAG, `moveFile file failed, message = ${err.message}; code = ${err.code}`);
    });
  }
}
