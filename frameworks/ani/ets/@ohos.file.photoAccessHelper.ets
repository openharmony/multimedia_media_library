/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { AsyncCallback, Callback, BusinessError } from '@ohos.base';
import image from '@ohos.multimedia.image';
import dataSharePredicates from '@ohos.data.dataSharePredicates';
import Context from 'application.Context';


class SizeImpl implements image.Size {
  height: int = 0;
  width: int = 0;
}

type ResolveVoid = (v: PromiseLike<void>) => void;
type RejectString = (e: BusinessError<string>) => void;

function businessError<T = void>(c: int, d?: string): BusinessError<T> {
  let err: BusinessError<T> = new BusinessError<T>();
  err.code = c;
  err.message = d ? d : "";
  return err;
}

function isNullish(d: NullishType): boolean {
  return (d === null || d === undefined) ? true : false;
}

class MediaLibraryAniError extends Error {
  code: number;

  constructor(code: int, message: string) {
    super('MediaLibraryAniError', message, undefined);
    this.code = code;
  }
}

export namespace photoAccessHelper {
  loadLibrary("photo_access_helper_ani");
  export native function getPhotoAccessHelper(context: Context): PhotoAccessHelper;

  export enum PhotoType {
    IMAGE = 1,
    VIDEO
  }

  export enum PhotoSubtype {
    DEFAULT = 0,
    SCREENSHOT = 1,
    MOVING_PHOTO = 3,
    BURST = 4,
  }

  export enum DynamicRangeType {
    SDR = 0,
    HDR = 1
  }

  export enum PositionType {
    LOCAL = 1 << 0,
    CLOUD = 1 << 1
  }

  export enum AnalysisType {
    ANALYSIS_AESTHETICS_SCORE = 0,
    ANALYSIS_LABEL,
    ANALYSIS_OCR,
    ANALYSIS_FACE,
    ANALYSIS_OBJECT,
    ANALYSIS_RECOMMENDATION,
    ANALYSIS_SEGMENTATION,
    ANALYSIS_COMPOSITION,
    ANALYSIS_SALIENCY,
    ANALYSIS_DETAIL_ADDRESS,
    ANALYSIS_HUMAN_FACE_TAG,
    ANALYSIS_HEAD_POSITION,
    ANALYSIS_BONE_POSE,
    ANALYSIS_VIDEO_LABEL,
    ANALYSIS_HIGHLIGHT,
    ANALYSIS_MULTI_CROP
  }

  export enum RecommendationType {
    QR_OR_BAR_CODE = 1,
    QR_CODE = 2,
    BAR_CODE = 3,
    ID_CARD = 4,
    PROFILE_PICTURE = 5,
    PASSPORT = 6,
    BANK_CARD = 7,
    DRIVER_LICENSE = 8,
    DRIVING_LICENSE = 9,
    FEATURED_SINGLE_PORTRAIT = 10
  }

  export enum DeliveryMode {
    FAST_MODE = 0,
    HIGH_QUALITY_MODE = 1,
    BALANCE_MODE = 2
  }

  export enum CompatibleMode {
    ORIGINAL_FORMAT_MODE = 0,
    COMPATIBLE_FORMAT_MODE = 1
  }

  export interface MediaAssetProgressHandler {
    onProgress(progress: number): void;
  }

  export enum SourceMode {
    ORIGINAL_MODE = 0,
    EDITED_MODE = 1
  }

  export enum PhotoPermissionType {
    TEMPORARY_READ_IMAGEVIDEO = 0,
    PERSISTENT_READ_IMAGEVIDEO = 1
  }

  export enum HideSensitiveType {
    HIDE_LOCATION_AND_SHOOTING_PARAM = 0,
    HIDE_LOCATION_ONLY = 1,
    HIDE_SHOOTING_PARAM_ONLY = 2,
    NO_HIDE_SENSITIVE_TYPE = 3
  }

  export enum AuthorizationMode {
    SHORT_TIME_AUTHORIZATION = 0
  }

  export enum CompleteButtonText {
    TEXT_DONE = 0,
    TEXT_SEND = 1,
    TEXT_ADD = 2,
  }

  export enum WatermarkType {
    DEFAULT = 0,
    BRAND_COMMON = 1,
    COMMON = 2,
    BRAND = 3,
  }

  export interface RequestOptions {
    deliveryMode: DeliveryMode;
    sourceMode?: SourceMode;
    compatibleMode?: CompatibleMode;
    mediaAssetProgressHandler?: MediaAssetProgressHandler;
  }

  export interface MediaAssetDataHandler<T> {
    onDataPrepared(data: T, map?: Map<string, string>): void;
  }

  export interface QuickImageDataHandler<T> {
    onDataPrepared(data: T, imageSource: image.ImageSource, map: Map<string, string>): void;
  }

  export interface PhotoProxy {}

  export class MediaAssetManager {
  }

  export type MemberType = number | string | boolean;

  export interface PhotoAsset {
    readonly uri: string;
    readonly photoType: PhotoType;
    readonly displayName: string;

    get(member: string): MemberType;
    set(member: string, value: string): void;
    commitModify(callback: AsyncCallback<void>): void;
    commitModify(): Promise<void>;
    open(mode: string, callback: AsyncCallback<number | undefined>): void;
    open(mode: string): Promise<number>;
    close(fd: number, callback: AsyncCallback<void>): void;
    close(fd: number): Promise<void>;
    getThumbnail(callback: AsyncCallback<image.PixelMap | undefined>): void;
    getThumbnail(size: image.Size, callback: AsyncCallback<image.PixelMap | undefined>): void;
    getThumbnail(size?: image.Size): Promise<image.PixelMap>;
    setFavorite(favoriteState: boolean, callback: AsyncCallback<void>): void;
    setFavorite(favoriteState: boolean): Promise<void>;
    setHidden(hiddenState: boolean, callback: AsyncCallback<void>): void;
    setHidden(hiddenState: boolean): Promise<void>;
    setUserComment(userComment: string, callback: AsyncCallback<void>): void;
    setUserComment(userComment: string): Promise<void>;
    getAnalysisData(analysisType: AnalysisType): Promise<string>;
  }

  class PhotoAssetHandle implements PhotoAsset {
    readonly uri: string = "";
    readonly photoType: PhotoType;
    readonly displayName: string = "";

    private nativePhotoAsset: long = 0;
    constructor(context: long) {
      if (this.nativePhotoAsset == 0) {
        this.nativePhotoAsset = context;
      }
    }

    native static create(): PhotoAsset;
    native set(member: string, value: string): void;
    native get(member: string): MemberType;
    native commitModifySync(): void;
    native openSync(mode: string): number;
    native closeSync(fd: number): void;
    native getThumbnailSync(size?: image.Size): image.PixelMap;
    native setFavoriteSync(favoriteState: boolean): void;
    native setHiddenSync(hiddenState: boolean): void;
    native setUserCommentSync(userComment: string): void;
    native getAnalysisDataSync(analysisType: AnalysisType): string;

    commitModify(): Promise<void> {
      return new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: RejectString) => {
        let cb = (): PromiseLike<void> => { this.commitModifySync() };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret === null || ret === undefined) {
            let err: BusinessError<string> = {
              code: -1,
              data: "Operation failed",
              name: "",
              message: ""
            };
            reject(err);
          } else {
            resolve(ret as PromiseLike<void>);
          }
        });
      });
    }
    commitModify(callback: AsyncCallback<void, void>): void {
      let task = new taskpool.Task(() =>this.commitModifySync());
      let p1 = taskpool.execute(task);
      p1.then((ret: NullishType) => {
        let eNull: BusinessError<void> = {
          code: -1,
          name: "",
          message: ""
        };
        if (ret === null || ret === undefined) {
          eNull.code = -1;
          callback(eNull, undefined);
        } else {
          eNull.code = 0;
          callback(eNull, undefined);
        }
      });
    }

    open(mode: string): Promise<number> {
      return new Promise<number>((resolve : (v: number) => void, reject : RejectString) => {
        let cb = (): number => { return this.openSync(mode) };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret === null || ret === undefined) {
            let err: BusinessError<string> = {
              code: -1,
              data: "Operation failed",
              name: "",
              message: ""
            };
            reject(err);
          } else {
            resolve(ret as number);
          }
        });
      });
    }
    open(mode: string, callback: AsyncCallback<number | undefined, void>): void {
      let task = new taskpool.Task(() =>this.openSync(mode));
      let p1 = taskpool.execute(task);
      p1.then((ret: NullishType) => {
        let eNull: BusinessError<void> = {
          code: -1,
          name: "",
          message: ""
        };
        if (ret === null || ret === undefined) {
          eNull.code = -1;
          callback(eNull, undefined);
        } else {
          let result = ret as number;
          eNull.code = 0;
          callback(eNull, result);
        }
      });
    }

    close(fd: number): Promise<void> {
      return new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: RejectString) => {
        let cb = (): PromiseLike<void> => { this.closeSync(fd) };
        taskpool.execute(cb).then((ret: NullishType): void => {
          resolve(ret as PromiseLike<void>);
        });
      });
    }
    close(fd: number, callback: AsyncCallback<void, void>): void {
      let task = new taskpool.Task(() =>this.closeSync(fd));
      let p1 = taskpool.execute(task);
      p1.then((ret: NullishType) => {
        let eNull: BusinessError<void> = {
          code: -1,
          name: "",
          message: ""
        };
        if (ret === null || ret === undefined) {
          eNull.code = -1;
          callback(eNull, undefined);
        } else {
          eNull.code = 0;
          callback(eNull, undefined);
        }
      });
    }

    getThumbnail(size?: image.Size): Promise<image.PixelMap> {
      return new Promise<image.PixelMap>((resolve : (v: image.PixelMap) => void, reject: RejectString) => {
        let cb = (): image.PixelMap => { return this.getThumbnailSync(size) };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret === null || ret === undefined) {
            let ret1: BusinessError<string> = {
              code: -1,
              data: "Operation failed",
              name: "",
              message: ""
            };
            reject(ret1);
          } else {
            let pixelMap = ret as image.PixelMap;
            resolve(pixelMap);
          }
        });
      });
    }

    getThumbnail(callback: AsyncCallback<image.PixelMap | undefined, void>): void {
      let task = new taskpool.Task(() =>this.getThumbnailSync());
      let p1 = taskpool.execute(task);
      p1.then((ret: NullishType) => {
        let eNull: BusinessError<void> = {
          code: -1,
          name: "",
          message: ""
        };
        if (ret === null || ret === undefined) {
          eNull.code = -1;
          callback(eNull, undefined);
        } else {
          let result = ret as image.PixelMap;
          eNull.code = 0;
          callback(eNull, result);
        }
      });
    }

    getThumbnail(size: image.Size, callback: AsyncCallback<image.PixelMap | undefined, void>): void {
      let task = new taskpool.Task(() =>this.getThumbnailSync(size));
      let p1 = taskpool.execute(task);
      p1.then((ret: NullishType) => {
        let eNull: BusinessError<void> = {
          code: -1,
          name: "",
          message: ""
        };
        if (ret === null || ret === undefined) {
          eNull.code = -1;
          callback(eNull, undefined);
        } else {
          let result = ret as image.PixelMap;
          eNull.code = 0;
          callback(eNull, result);
        }
      });
    }

    setFavorite(favoriteState: boolean): Promise<void> {
    return new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: RejectString) => {
      let cb = (): PromiseLike<void> => { this.setFavoriteSync(favoriteState) };
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret === null || ret === undefined) {
          let err: BusinessError<string> = {
            code: -1,
            data: "Operation failed",
            name: "",
            message: ""
          };
          reject(err);
        } else {
          resolve(ret as PromiseLike<void>);
        }
      });
    });
    }

    setFavorite(favoriteState: boolean, callback: AsyncCallback<void, void>): void {
      let task = new taskpool.Task(() =>this.setFavoriteSync(favoriteState));
      let p1 = taskpool.execute(task);
      p1.then((ret: NullishType) => {
        let eNull: BusinessError<void> = {
          code: -1,
          name: "",
          message: ""
        };
        if (ret === null || ret === undefined) {
          eNull.code = -1;
          callback(eNull, undefined);
        } else {
          eNull.code = 0;
          callback(eNull, undefined);
        }
      });
    }

    setHidden(hiddenState: boolean): Promise<void> {
      return new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: RejectString) => {
        let cb = (): PromiseLike<void> => { this.setHiddenSync(hiddenState) };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret === null || ret === undefined) {
            let err: BusinessError<string> = {
              code: -1,
              data: "Operation failed",
              name: "",
              message: ""
            };
            reject(err);
          } else {
            resolve(ret as PromiseLike<void>);
          }
        });
      });
    }

    setHidden(hiddenState: boolean, callback: AsyncCallback<void, void>): void {
      let task = new taskpool.Task(() =>this.setHiddenSync(hiddenState));
      let p1 = taskpool.execute(task);
      p1.then((ret: NullishType) => {
        let eNull: BusinessError<void> = {
          code: -1,
          name: "",
          message: ""
        };
        if (ret === null || ret === undefined) {
          eNull.code = -1;
          callback(eNull, undefined);
        } else {
          eNull.code = 0;
          callback(eNull, undefined);
        }
      });
    }

    setUserComment(userComment: string): Promise<void> {
      return new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: RejectString) => {
        let cb = (): PromiseLike<void> => { this.setUserCommentSync(userComment) };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret === null || ret === undefined) {
            let err: BusinessError<string> = {
              code: -1,
              data: "Operation failed",
              name: "",
              message: ""
            };
            reject(err);
          } else {
            resolve(ret as PromiseLike<void>);
          }
        });
      });
    }

    setUserComment(userComment: string, callback: AsyncCallback<void, void>): void {
      let task = new taskpool.Task(() =>this.setUserCommentSync(userComment));
      let p1 = taskpool.execute(task);
      p1.then((ret: NullishType) => {
        let eNull: BusinessError<void> = {
          code: -1,
          name: "",
          message: ""
        };
        if (ret === null || ret === undefined) {
          eNull.code = -1;
          callback(eNull, undefined);
        } else {
          eNull.code = 0;
          callback(eNull, undefined);
        }
      });
    }

    getAnalysisData(analysisType: AnalysisType): Promise<string> {
      return new Promise<string>((resolve: (v: string) => void, reject: RejectString) => {
        let cb = (): string => { return this.getAnalysisDataSync(analysisType) };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret === null || ret === undefined) {
            let err: BusinessError<string> = {
              code: -1,
              data: "Operation failed",
              name: "",
              message: ""
            };
            reject(err);
          } else {
            resolve(ret as string);
          }
        });
      });
    }

    getAnalysisData(analysisType: AnalysisType, callback: AsyncCallback<string | undefined, void>): void {
      let task = new taskpool.Task(() =>this.getAnalysisDataSync(analysisType));
      let p1 = taskpool.execute(task);
      p1.then((ret: NullishType) => {
        let eNull: BusinessError<void> = {
          code: -1,
          name: "",
          message: ""
        };
        if (ret === null || ret === undefined) {
          eNull.code = -1;
          callback(eNull, undefined);
        } else {
          let result = ret as string;
          eNull.code = 0;
          callback(eNull, result);
        }
      });
    }
  }


  export enum PhotoKeys {
    URI = 'uri',
    PHOTO_TYPE = 'media_type',
    DISPLAY_NAME = 'display_name',
    SIZE = 'size',
    DATE_ADDED = 'date_added',
    DATE_MODIFIED = 'date_modified',
    DURATION = 'duration',
    WIDTH = 'width',
    HEIGHT = 'height',
    DATE_TAKEN = 'date_taken',
    ORIENTATION = 'orientation',
    FAVORITE = 'is_favorite',
    TITLE = 'title',
    POSITION = 'position',
    DATE_TRASHED = 'date_trashed',
    HIDDEN = 'hidden',
    USER_COMMENT = 'user_comment',
    CAMERA_SHOT_KEY = 'camera_shot_key',
    DATE_YEAR = 'date_year',
    DATE_MONTH = 'date_month',
    DATE_DAY = 'date_day',
    PENDING = 'pending',
    DATE_ADDED_MS = 'date_added_ms',
    DATE_MODIFIED_MS = 'date_modified_ms',
    DATE_TRASHED_MS = 'date_trashed_ms',
    PHOTO_SUBTYPE = 'subtype',
    MOVING_PHOTO_EFFECT_MODE = 'moving_photo_effect_mode',
    DYNAMIC_RANGE_TYPE = 'dynamic_range_type',
    COVER_POSITION = 'cover_position',
    BURST_KEY = 'burst_key',
    THUMBNAIL_READY = 'thumbnail_ready',
    LCD_SIZE = 'lcd_size',
    THM_SIZE = 'thm_size',
    DETAIL_TIME = 'detail_time',
    DATE_TAKEN_MS = 'date_taken_ms',
    CE_AVAILABLE = 'ce_available',
    SUPPORTED_WATERMARK_TYPE = 'supported_watermark_type'
  }

  export enum AlbumKeys {
    URI = 'uri',
    ALBUM_NAME = 'album_name'
  }

  export enum HiddenPhotosDisplayMode {
    ASSETS_MODE,
    ALBUMS_MODE
  }

  export interface FetchOptions {
    fetchColumns: Array<string>;
    predicates: dataSharePredicates.DataSharePredicates;
  }

  export interface PhotoCreateOptions {
    subtype?: PhotoSubtype;
    cameraShotKey?: string;
  }

  export interface PhotoCreationConfig {
    title?: string;
    fileNameExtension: string;
    photoType: PhotoType;
    subtype?: PhotoSubtype;
  }

  export interface CreateOptions {
    title?: string;
    subtype?: PhotoSubtype;
  }

  export interface RequestPhotoOptions {
    size?: image.Size;
    requestPhotoType?: RequestPhotoType;
  }

  export interface FetchResult<T> {
    getCount(): number;
    isAfterLast(): boolean;
    getFirstObject(callback: AsyncCallback<T | undefined>): void;
    getFirstObject(): Promise<T>;
    getNextObject(callback: AsyncCallback<T | undefined>): void;
    getNextObject(): Promise<T>;
    getAllObjects(callback: AsyncCallback<Array<T> | undefined>): void;
    getAllObjects(): Promise<Array<T>>;
    close(): void;
  }

  class FetchResultHandle<T> implements FetchResult<T> {
    private nativeValue: long = 0;

    constructor(value: long) {
        this.nativeValue = value;
    }
    native getCount(): number;
    native getFirstObjectSync(): T;
    native getNextObjectSync(): T;
    native getAllObjectsSync(): Array<T>;
    native close(): void;

    isAfterLast(): boolean {
      return false;
    }
    getFirstObject(callback: AsyncCallback<T | undefined>): void {}
    getFirstObject(): Promise<T> {
      return new Promise<T>((resolve: (v: T) => void, reject: RejectString) => {
        let cb = (): T => { return this.getFirstObjectSync() };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret === null || ret === undefined) {
            let err: BusinessError<string> = {
              code: -1,
              data: "Operation failed",
              name: "",
              message: ""
            };
            reject(err);
          } else {
            let result = ret as T;
            resolve(result);
          }
        });
      });
    }

    getNextObject(callback: AsyncCallback<T | undefined>): void {}
    getNextObject(): Promise<T> {
      return new Promise<T>((resolve: (v: T) => void, reject: RejectString) => {
        let cb = (): T => { return this.getNextObjectSync() };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret === null || ret === undefined) {
            let err: BusinessError<string> = {
              code: -1,
              data: "Operation failed",
              name: "",
              message: ""
            };
            reject(err);
          } else {
            let result = ret as T;
            resolve(result);
          }
        });
      });
    }

    getAllObjects(callback: AsyncCallback<Array<T> | undefined, void>): void {
      let task = new taskpool.Task(() => this.getAllObjectsSync());
      let p1 = taskpool.execute(task);
      p1.then((ret: NullishType) => {
        let eNull: BusinessError<void> = {
          code: -1,
          name: "",
          message: ""
        };
        if (ret === null || ret === undefined) {
          eNull.code = -1;
          callback(eNull, undefined);
        } else {
          let result = ret as Array<T>;
          eNull.code = 0;
          callback(eNull, result);
        }
      });
    }
    getAllObjects(): Promise<Array<T>> {
      return new Promise<Array<T>>((resolve: (v: Array<T>) => void, reject: RejectString) => {
        let blockQueue: containers.BlockingQueue<Array<T>> = new containers.ArrayBlockingQueue<Array<T>>(2);
        let cb = (): Array<T> => {
          let result = this.getAllObjectsSync()
          blockQueue.push(result)
          return result
        };

        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret === null || ret === undefined) {
            let err: BusinessError<string> = {
              code: -1,
              data: "Operation failed",
              name: "",
              message: ""
            };
            reject(err);
          } else {
            let result = ret as Array<T>;
            resolve(result);
          }
        });

        blockQueue.pop();
      });
    }
  }

  export enum AlbumType {
    USER = 0,
    SYSTEM = 1024,
    SMART = 4096
  }

  export enum AlbumSubtype {
    USER_GENERIC = 1,
    FAVORITE = 1025,
    VIDEO,
    HIDDEN,
    TRASH,
    SCREENSHOT,
    CAMERA,
    IMAGE = 1031,
    CLOUD_ENHANCEMENT = 1032,
    SOURCE_GENERIC = 2049,
    CLASSIFY = 4097,
    GEOGRAPHY_LOCATION = 4099,
    GEOGRAPHY_CITY,
    SHOOTING_MODE,
    PORTRAIT,
    GROUP_PHOTO,
    HIGHLIGHT = 4104,
    HIGHLIGHT_SUGGESTIONS,
    ANY = 2147483647
  }

  export enum RequestPhotoType {
    REQUEST_ALL_THUMBNAILS = 0,
    REQUEST_FAST_THUMBNAIL,
    REQUEST_QUALITY_THUMBNAIL
  }

  export interface AbsAlbum {
    readonly albumType: AlbumType;
    readonly albumSubtype: AlbumSubtype;
    albumName: string;
    readonly albumUri: string;
    readonly count: number;
    readonly coverUri: string;

    getAssets(options: FetchOptions, callback: AsyncCallback<FetchResult<PhotoAsset> | undefined>): void;
    getAssets(options: FetchOptions): Promise<FetchResult<PhotoAsset>>;
    getSharedPhotoAssets(options: FetchOptions): Array<SharedPhotoAsset>;
  }

  export interface Album extends AbsAlbum {
    readonly imageCount?: number;
    readonly videoCount?: number;

    commitModify(callback: AsyncCallback<void>): void;
    commitModify(): Promise<void>;
    addAssets(assets: Array<PhotoAsset>, callback: AsyncCallback<void>): void;
    addAssets(assets: Array<PhotoAsset>): Promise<void>;
    removeAssets(assets: Array<PhotoAsset>, callback: AsyncCallback<void>): void;
    removeAssets(assets: Array<PhotoAsset>): Promise<void>;
    recoverAssets(assets: Array<PhotoAsset>, callback: AsyncCallback<void>): void;
    recoverAssets(assets: Array<PhotoAsset>): Promise<void>;
    deleteAssets(assets: Array<PhotoAsset>, callback: AsyncCallback<void>): void;
    deleteAssets(assets: Array<PhotoAsset>): Promise<void>;
    setCoverUri(uri: string, callback: AsyncCallback<void>): void;
    setCoverUri(uri: string): Promise<void>;
    getFaceId(): Promise<string>;
  }

  class AlbumHandle implements Album {
    readonly albumType: AlbumType;
    readonly albumSubtype: AlbumSubtype;
    albumName: string = '';
    readonly albumUri: string = '';
    readonly count: number;
    readonly coverUri: string = '';
    readonly imageCount: number | undefined = undefined;
    readonly videoCount: number | undefined = undefined;
    private nativePhotoAlbum: long = 0;

    constructor(nativePtr: long) {
      if (this.nativePhotoAlbum == 0) {
        this.nativePhotoAlbum = nativePtr;
        this.imageCount = this.getImageCount();
        this.videoCount = this.getVideoCount();
      }
    }

    getAssets(options: FetchOptions, callback: AsyncCallback<FetchResult<PhotoAsset> | undefined>): void {
      let cb = (): MediaLibraryAniError | FetchResult<PhotoAsset> => {
        try {
          return this.getAssetsInner(options);
        } catch(e) {
          return e as MediaLibraryAniError;
        }
      };
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof MediaLibraryAniError) {
          let err = ret as MediaLibraryAniError;
          callback(businessError(err.code as int, err.message), undefined);
        } else {
          if (isNullish(ret)) {
            callback(businessError(-1, "Operation failed"), undefined);
          } else {
            callback(businessError(0), ret as FetchResult<PhotoAsset>);
          }
        }
      });
    }

    getAssets(options: FetchOptions): Promise<FetchResult<PhotoAsset>> {
      return new Promise<FetchResult<PhotoAsset>>((resolve: (v: FetchResult<PhotoAsset>) => void,
        reject: RejectString) => {
          let cb = (): FetchResult<PhotoAsset> | MediaLibraryAniError => {
            try {
              return this.getAssetsInner(options);
            } catch(e) {
              return e as MediaLibraryAniError;
            }
          };
          taskpool.execute(cb).then((ret: NullishType): void => {
            if (ret instanceof MediaLibraryAniError) {
              let err = ret as MediaLibraryAniError;
              reject(businessError<string>(err.code as int, err.message));
            } else {
              if (isNullish(ret)) {
                reject(businessError<string>(-1, "Operation failed"));
              } else {
                resolve(ret as FetchResult<PhotoAsset>);
              }
            }
          });
      });
    }

    getSharedPhotoAssets(options: FetchOptions): Array<SharedPhotoAsset> {
      return new Array<SharedPhotoAsset>();
    }

    commitModify(callback: AsyncCallback<void>): void {
      let cb = (): MediaLibraryAniError | undefined => {
        try {
          this.commitModifyInner();
          return undefined;
        } catch(e) {
          return e as MediaLibraryAniError;
        }
      }
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (isNullish(ret)) {
          callback(businessError(0), undefined);
        } else {
          let err = ret as MediaLibraryAniError;
          callback(businessError(err.code as int, err.message), undefined);
        }
      });
    }

    commitModify(): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: (e: BusinessError<void>) => void): void => {
        let cb = (): MediaLibraryAniError | undefined => {
          try {
            this.commitModifyInner();
            return undefined;
          } catch(e) {
            return e as MediaLibraryAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (isNullish(ret)) {
            resolve(undefined);
          } else {
            let err = ret as MediaLibraryAniError;
            reject(businessError(err.code as int, err.message));
          }
        });
      });
    }

    addAssets(assets: Array<PhotoAsset>, callback: AsyncCallback<void>): void {
      let cb = (): MediaLibraryAniError | undefined => {
        try {
          this.addAssetsInner(assets);
          return undefined;
        } catch(e) {
          return e as MediaLibraryAniError;
        }
      }
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (isNullish(ret)) {
          callback(businessError(0), undefined);
        } else {
          let err = ret as MediaLibraryAniError;
          callback(businessError(err.code as int, err.message), undefined);
        }
      });
    }

    addAssets(assets: Array<PhotoAsset>): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: (e: BusinessError<void>) => void): void => {
        let cb = (): MediaLibraryAniError | undefined => {
          try {
            this.addAssetsInner(assets);
            return undefined;
          } catch(e) {
            return e as MediaLibraryAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (isNullish(ret)) {
            resolve(undefined);
          } else {
            let err = ret as MediaLibraryAniError;
            reject(businessError(err.code as int, err.message));
          }
        });
      });
    }

    removeAssets(assets: Array<PhotoAsset>, callback: AsyncCallback<void>): void {
      let cb = (): MediaLibraryAniError | undefined => {
        try {
          this.removeAssetsInner(assets);
          return undefined;
        } catch(e) {
          return e as MediaLibraryAniError;
        }
      }
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (isNullish(ret)) {
          callback(businessError(0), undefined);
        } else {
          let err = ret as MediaLibraryAniError;
          callback(businessError(err.code as int, err.message), undefined);
        }
      });
    }

    removeAssets(assets: Array<PhotoAsset>): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: (e: BusinessError<void>) => void): void => {
        let cb = (): MediaLibraryAniError | undefined => {
          try {
            this.removeAssetsInner(assets);
            return undefined;
          } catch(e) {
            return e as MediaLibraryAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (isNullish(ret)) {
            resolve(undefined);
          } else {
            let err = ret as MediaLibraryAniError;
            reject(businessError(err.code as int, err.message));
          }
        });
      });
    }

    recoverAssets(assets: Array<PhotoAsset>, callback: AsyncCallback<void>): void {
      let cb = (): MediaLibraryAniError | undefined => {
        try {
          this.recoverAssetsInner(assets);
          return undefined;
        } catch(e) {
          return e as MediaLibraryAniError;
        }
      }
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (isNullish(ret)) {
          callback(businessError(0), undefined);
        } else {
          let err = ret as MediaLibraryAniError;
          callback(businessError(err.code as int, err.message), undefined);
        }
      });
    }

    recoverAssets(assets: Array<PhotoAsset>): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: (e: BusinessError<void>) => void): void => {
        let cb = (): MediaLibraryAniError | undefined => {
          try {
            this.recoverAssetsInner(assets);
            return undefined;
          } catch(e) {
            return e as MediaLibraryAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (isNullish(ret)) {
            resolve(undefined);
          } else {
            let err = ret as MediaLibraryAniError;
            reject(businessError(err.code as int, err.message));
          }
        });
      });
    }

    deleteAssets(assets: Array<PhotoAsset>, callback: AsyncCallback<void>): void {
      let cb = (): MediaLibraryAniError | undefined => {
        try {
          this.deleteAssetsInner(assets);
          return undefined;
        } catch(e) {
          return e as MediaLibraryAniError;
        }
      }
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (isNullish(ret)) {
          callback(businessError(0), undefined);
        } else {
          let err = ret as MediaLibraryAniError;
          callback(businessError(err.code as int, err.message), undefined);
        }
      });
    }

    deleteAssets(assets: Array<PhotoAsset>): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: (e: BusinessError<void>) => void): void => {
        let cb = (): MediaLibraryAniError | undefined => {
          try {
            this.deleteAssetsInner(assets);
            return undefined;
          } catch(e) {
            return e as MediaLibraryAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (isNullish(ret)) {
            resolve(undefined);
          } else {
            let err = ret as MediaLibraryAniError;
            reject(businessError(err.code as int, err.message));
          }
        });
      });
    }

    setCoverUri(uri: string, callback: AsyncCallback<void>): void {
      let cb = (): MediaLibraryAniError | undefined => {
        try {
          this.setCoverUriInner(uri);
          return undefined;
        } catch(e) {
          return e as MediaLibraryAniError;
        }
      }
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (isNullish(ret)) {
          callback(businessError(0), undefined);
        } else {
          let err = ret as MediaLibraryAniError;
          callback(businessError(err.code as int, err.message), undefined);
        }
      });
    }

    setCoverUri(uri: string): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: (e: BusinessError<void>) => void): void => {
        let cb = (): MediaLibraryAniError | undefined => {
          try {
            this.setCoverUriInner(uri);
            return undefined;
          } catch(e) {
            return e as MediaLibraryAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (isNullish(ret)) {
            resolve(undefined);
          } else {
            let err = ret as MediaLibraryAniError;
            reject(businessError(err.code as int, err.message));
          }
        });
      });
    }

    getFaceId(): Promise<string> {
      return new Promise<string>((resolve: (v: string) => void, reject: RejectString) => {
        let cb = (): string | MediaLibraryAniError => {
          try {
            return this.getFaceIdInner();
          } catch(e) {
            return e as MediaLibraryAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret instanceof MediaLibraryAniError) {
            let err = ret as MediaLibraryAniError;
            reject(businessError<string>(err.code as int, err.message));
          } else {
            if (isNullish(ret)) {
              reject(businessError<string>(-1, "Operation failed"));
            } else {
              resolve(ret as string);
            }
          }
        });
      });
    }

    native getAssetsInner(options: FetchOptions): FetchResult<PhotoAsset>;
    native getAssetsSync(options: FetchOptions): Array<PhotoAsset>;
    native commitModifyInner(): void;
    native addAssetsInner(assets: Array<PhotoAsset>): void;
    native removeAssetsInner(assets: Array<PhotoAsset>): void;
    native recoverAssetsInner(assets: Array<PhotoAsset>): void;
    native deleteAssetsInner(assets: Array<PhotoAsset>): void;
    native setCoverUriInner(uri: string): void;
    native getFaceIdInner(): string;
    native getImageCount(): number;
    native getVideoCount(): number;
  }

  export interface PhotoAccessHelper {
    getAssets(options: FetchOptions, callback: AsyncCallback<FetchResult<PhotoAsset> | undefined>): void;
    getAssets(options: FetchOptions): Promise<FetchResult<PhotoAsset>>;
    getAssetsSync(options: FetchOptions): Array<PhotoAsset>;
    getFileAssetsInfo(options: FetchOptions): Array<FileAssetInfo>;
    getAlbums(type: AlbumType, subtype: AlbumSubtype, options: FetchOptions): Promise<FetchResult<Album>>;
    stopThumbnailCreationTask(taskId: number): void;
    startCreateThumbnailTask(predicate: dataSharePredicates.DataSharePredicates): int;
    getBurstAssets(burstKey: string, options: FetchOptions): Promise<FetchResult<PhotoAsset>>;
    createAsset(displayName: string, callback: AsyncCallback<PhotoAsset | undefined>): void;
    createAsset(displayName: string): Promise<PhotoAsset>;
    createAsset(displayName: string, options: PhotoCreateOptions): Promise<PhotoAsset>;
    createAsset(displayName: string, options: PhotoCreateOptions,
      callback: AsyncCallback<PhotoAsset | undefined>): void;
    createAsset(photoType: PhotoType, extension: string, options: CreateOptions,
      callback: AsyncCallback<string | undefined>): void;
    createAsset(photoType: PhotoType, extension: string, callback: AsyncCallback<string | undefined>): void;
    createAsset(photoType: PhotoType, extension: string, options?: CreateOptions): Promise<string>;
  }

  class PhotoAccessHelperHandle implements PhotoAccessHelper {
    private nativePhotoAccessHelper: long = 0;

    constructor(nativePtr: long) {
      if (this.nativePhotoAccessHelper == 0) {
        this.nativePhotoAccessHelper = nativePtr;
      }
    }

    getAssets(options: FetchOptions, callback: AsyncCallback<FetchResult<PhotoAsset> | undefined>): void {
      let cb = (): MediaLibraryAniError | FetchResult<PhotoAsset> => {
        try {
          return this.getAssetsInner(options);
        } catch(e) {
          return e as MediaLibraryAniError;
        }
      };
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof MediaLibraryAniError) {
          let err = ret as MediaLibraryAniError;
          callback(businessError(err.code as int, err.message), undefined);
        } else {
          if (isNullish(ret)) {
            callback(businessError(-1, "Operation failed"), undefined);
          } else {
            callback(businessError(0), ret as FetchResult<PhotoAsset>);
          }
        }
      });
    }

    getAssets(options: FetchOptions): Promise<FetchResult<PhotoAsset>> {
      return new Promise<FetchResult<PhotoAsset>>((resolve: (v: FetchResult<PhotoAsset>) => void, reject: RejectString) => {
        let blockQueue: containers.BlockingQueue<FetchResult<PhotoAsset>> = new containers.ArrayBlockingQueue<FetchResult<PhotoAsset>>(2);
        let cb = (): FetchResult<PhotoAsset> => {
          let result = this.getAssetsInner(options)
          blockQueue.push(result)
          return result
        };

        taskpool.execute(cb).then((buffer: NullishType): void => {
          if (buffer === null || buffer === undefined) {
            let error: BusinessError<string> = {
              code: -1,
              data: "Operation failed",
              name: "",
              message: ""
            };
            reject(error);
          } else {
            resolve(buffer as FetchResult<PhotoAsset>);
          }
        });

        blockQueue.pop();
      });
    }

    getAlbums(type: AlbumType, subtype: AlbumSubtype, options: FetchOptions): Promise<FetchResult<Album>> {
      return new Promise<FetchResult<Album>>((resolve: (v: FetchResult<Album>) => void, reject: RejectString) => {
        let cb = (): FetchResult<Album> => { return this.getAlbumsInner(type, subtype, options) };
        taskpool.execute(cb).then((buffer: NullishType): void => {
          if (buffer === null || buffer === undefined) {
            let error: BusinessError<string> = {
              code: -1,
              data: "Operation failed",
              name: "",
              message: ""
            };
            reject(error);
          } else {
            resolve(buffer as FetchResult<Album>);
          }
        });
      });
    }

    getBurstAssets(burstKey: string, options: FetchOptions): Promise<FetchResult<PhotoAsset>> {
      return new Promise<FetchResult<PhotoAsset>>((resolve: (v: FetchResult<PhotoAsset>) => void,
        reject: RejectString) => {
        let emptyResult: FetchResult<PhotoAsset> = new FetchResultHandle<PhotoAsset>(0);
        resolve(emptyResult);
      });
    }

    createAsset(displayName: string, callback: AsyncCallback<PhotoAsset | undefined>): void {}

    createAsset(displayName: string): Promise<PhotoAsset> {
      return new Promise<PhotoAsset>((resolve: (v: PhotoAsset) => void, reject: (e: BusinessError<string>) => void) => {
          let emptyResult: PhotoAsset = new PhotoAssetHandle(0);
          resolve(emptyResult);
        });
    }

    createAsset(displayName: string, options: PhotoCreateOptions): Promise<PhotoAsset> {
      return new Promise<PhotoAsset>((resolve: (v: PhotoAsset) => void, reject: (e: BusinessError<string>) => void) => {
        let emptyResult: PhotoAsset = new PhotoAssetHandle(0);
        resolve(emptyResult);
      });
    }

    createAsset(displayName: string, options: PhotoCreateOptions,
      callback: AsyncCallback<PhotoAsset | undefined>): void {}

    createAsset(photoType: PhotoType, extension: string, options: CreateOptions,
      callback: AsyncCallback<string | undefined>): void {}

    createAsset(photoType: PhotoType, extension: string, callback: AsyncCallback<string | undefined>): void {}

    createAsset(photoType: PhotoType, extension: string, options?: CreateOptions): Promise<string> {
      return new Promise<string>((resolve: (v: string) => void, reject: (e: BusinessError<string>) => void) => {
        let emptyResult: string = "";
        resolve(emptyResult);
      });
    }

    native getAlbumsInner(type: AlbumType, subtype: AlbumSubtype, options: FetchOptions): FetchResult<Album>;
    native release(): void;
    native applyChanges(mediaChangeRequest: MediaChangeRequest): void;
    native createAsset1(displayName: string): PhotoAsset;
    native getAssetsSync(options: FetchOptions): Array<PhotoAsset>;
    native getFileAssetsInfo(options: FetchOptions): Array<FileAssetInfo>;
    native getAssetsInner(options: FetchOptions): FetchResult<PhotoAsset>;
    native stopThumbnailCreationTask(taskId: number): void;
    native startCreateThumbnailTask(predicate: dataSharePredicates.DataSharePredicates): int;
  }

  export interface FormInfo {
    formId: string;
    uri: string;
  }

  export enum NotifyType {
    NOTIFY_ADD,
    NOTIFY_UPDATE,
    NOTIFY_REMOVE,
    NOTIFY_ALBUM_ADD_ASSET,
    NOTIFY_ALBUM_REMOVE_ASSET
  }

  export enum DefaultChangeUri {
    DEFAULT_PHOTO_URI = 'file://media/Photo',
    DEFAULT_ALBUM_URI = 'file://media/PhotoAlbum',
    DEFAULT_HIDDEN_ALBUM_URI = 'file://media/HiddenAlbum'
  }

  export interface ChangeData {
    type: NotifyType;
    uris: Array<string>;
    extraUris: Array<string>;
  }

  class ChangeDataHandle implements ChangeData {
    constructor() {}
    type: NotifyType;
    uris: Array<string> =  new Array<string>();
    extraUris: Array<string> =  new Array<string>();
  }

  export enum PhotoViewMIMETypes {
    IMAGE_TYPE = 'image/*',
    VIDEO_TYPE = 'video/*',
    IMAGE_VIDEO_TYPE = '*/*',
    MOVING_PHOTO_IMAGE_TYPE = 'image/movingPhoto'
  }

  export class BaseSelectOptions {
    MIMEType: PhotoViewMIMETypes | undefined;
    maxSelectNumber: number | undefined;
    isSearchSupported: boolean | undefined;
    isPhotoTakingSupported: boolean | undefined;
    recommendationOptions: RecommendationOptions | undefined;
    preselectedUris: Array<string> | undefined;
    isPreviewForSingleSelectionSupported: boolean | undefined;
  }

  export class PhotoSelectOptions extends BaseSelectOptions {
    isEditSupported: boolean | undefined;
    isOriginalSupported: boolean | undefined;
    subWindowName: string | undefined;
    themeColor: undefined;
    completeButtonText: CompleteButtonText | undefined;
  }

  export class RecommendationOptions {
    recommendationType: RecommendationType | undefined;
    textContextInfo: TextContextInfo | undefined;
  }

  export interface TextContextInfo {
    text?: string;
  }

  export class PhotoSelectResult {
    photoUris: Array<string> = new Array<string>();
    isOriginalPhoto: boolean = false;
  }

  export class PhotoViewPicker {
  }

  export class MediaAssetEditData {
    constructor(compatibleFormat: string, formatVersion: string) {
      this.compatibleFormat = compatibleFormat;
      this.formatVersion = formatVersion;
    }
    compatibleFormat: string;
    formatVersion: string;
    data: string;
  }

  export enum ResourceType {
    IMAGE_RESOURCE = 1,
    VIDEO_RESOURCE = 2,
    PHOTO_PROXY = 3,
    PRIVATE_MOVING_PHOTO_RESOURCE = 4
  }

  export enum ImageFileType {
    JPEG = 1,
    HEIF = 2
  }

  export enum MovingPhotoEffectMode {
    DEFAULT = 0,
    BOUNCE_PLAY = 1,
    LOOP_PLAY = 2,
    LONG_EXPOSURE = 3,
    MULTI_EXPOSURE = 4,
    CINEMA_GRAPH = 5,
    IMAGE_ONLY = 10
  }

  export enum VideoEnhancementType {
    QUALITY_ENHANCEMENT_LOCAL = 0,
    QUALITY_ENHANCEMENT_CLOUD = 1,
    QUALITY_ENHANCEMENT_LOCAL_AND_CLOUD = 2
  }

  export interface MediaChangeRequest {}

  export class MediaAssetChangeRequest implements MediaChangeRequest {
    constructor(asset: PhotoAsset) {}
  }

  export class MediaAssetsChangeRequest implements MediaChangeRequest {
    private assets: Array<PhotoAsset>;

    constructor(assets: Array<PhotoAsset>) {
      this.assets = assets;
    }

    setFavorite(favoriteState: boolean): void {}

    setHidden(hiddenState: boolean): void {}

    setUserComment(userComment: string): void {}
  }

  export class MediaAlbumChangeRequest implements MediaChangeRequest {
    constructor(album: Album) {}
  }

  export interface SharedPhotoAsset {
    fileId: number;
    uri: string;
    data: string;
    mediaType: PhotoType;
    displayName: string;
    size: number;
    dateAdded: number;
    dateModified: number;
    duration: number;
    width: number;
    height: number;
    dateTaken: number;
    orientation: number;
    isFavorite: boolean;
    title: string;
    position: PositionType;
    dateTrashed: number;
    hidden: boolean;
    userComment: string;
    cameraShotKey: string;
    dateYear: string;
    dateMonth: string;
    dateDay: string;
    pending: boolean;
    dateAddedMs: number;
    dateModifiedMs: number;
    dateTrashedMs: number;
    subtype: PhotoSubtype;
    movingPhotoEffectMode: MovingPhotoEffectMode;
    dynamicRangeType: DynamicRangeType;
    thumbnailReady: boolean;
    lcdSize: string;
    thmSize: string;
  }

  export interface MovingPhoto {
    requestContent(imageFileUri: string, videoFileUri: string): Promise<void>;
    requestContent(resourceType: ResourceType, fileUri: string): Promise<void>;
    requestContent(resourceType: ResourceType): Promise<ArrayBuffer>;
    getUri(): string;
  }

  export interface FileAssetInfo {
    file_id: number;
    uri: string;
    media_type: PhotoType;
    display_name: string;
    size: number;
    date_added: number;
    date_modified: number;
    duration: number;
    width: number;
    height: number;
    date_taken: number;
    orientation: number;
    is_favorite: boolean;
    title: string;
    position: PositionType;
    date_trashed: number;
    hidden: boolean;
    user_comment: string;
    camera_shot_key: string;
    date_year: string;
    date_month: string;
    date_day: string;
    pending: boolean;
    date_added_ms: number;
    date_modified_ms: number;
    date_trashed_ms: number;
    subtype: PhotoSubtype;
  }

  class FileAssetInfoHandle implements FileAssetInfo {
    file_id: number;
    uri: string = "";
    media_type: PhotoType;
    display_name: string = "";
    size: number;
    date_added: number;
    date_modified: number;
    duration: number;
    width: number;
    height: number;
    date_taken: number;
    orientation: number;
    is_favorite: boolean;
    title: string = "";
    position: PositionType;
    date_trashed: number;
    hidden: boolean;
    user_comment: string = "";
    camera_shot_key: string = "";
    date_year: string = "";
    date_month: string = "";
    date_day: string = "";
    pending: boolean;
    date_added_ms: number;
    date_modified_ms: number;
    date_trashed_ms: number;
    subtype: PhotoSubtype;
  }

  class MovingPhotoHandle implements MovingPhoto {
    private nativeMovingPhoto: long = 0;

    constructor(context: long) {
      if(this.nativeMovingPhoto == 0){
        this.nativeMovingPhoto = context;
      }
    }

    requestContent(imageFileUri: string, videoFileUri: string): Promise<void> {
      return new Promise<void>((resolve: ResolveVoid, reject: RejectString) => {
        let cb = (): PromiseLike<void> => { this.requestContent1(imageFileUri, videoFileUri) };
        taskpool.execute(cb).then((v: NullishType): void => {
          resolve(v as PromiseLike<void>);
        });
      });
    }
    requestContent(resourceType: ResourceType, fileUri: string): Promise<void> {
      return new Promise<void>((resolve: ResolveVoid, reject: RejectString) => {
        let cb = (): PromiseLike<void> => { this.requestContent2(resourceType, fileUri) }
        taskpool.execute(cb).then((v: NullishType): void => {
          resolve(v as PromiseLike<void>);
        });
      });
    }
    requestContent(resourceType: ResourceType): Promise<ArrayBuffer> {
      return new Promise<ArrayBuffer>((resolve: (v: ArrayBuffer) => void, reject: RejectString) => {
        let cb = (): ArrayBuffer => { return this.requestContent3(resourceType) };
        taskpool.execute(cb).then((buffer: NullishType): void => {
          if (buffer === null || buffer === undefined) {
            let error: BusinessError<string> = {
              code: -1,
              data: "Operation failed",
              name: "",
              message: ""
            };
            reject(error);
          } else {
            resolve(buffer as ArrayBuffer);
          }
        });
      });
    }

    native requestContent1(imageFileUri: string, videoFileUri: string): void;
    native requestContent2(resourceType: ResourceType, fileUri: string): void;
    native requestContent3(resourceType: ResourceType): ArrayBuffer;
    native getUri(): string;
  }

  export enum HighlightAlbumInfoType {
    COVER_INFO = 0,
    PLAY_INFO
  }

  export enum HighlightUserActionType {
    INSERTED_PIC_COUNT = 0,
    REMOVED_PIC_COUNT,
    SHARED_SCREENSHOT_COUNT,
    SHARED_COVER_COUNT,
    RENAMED_COUNT,
    CHANGED_COVER_COUNT,
    RENDER_VIEWED_TIMES = 100,
    RENDER_VIEWED_DURATION,
    ART_LAYOUT_VIEWED_TIMES,
    ART_LAYOUT_VIEWED_DURATION
  }

  export enum ThumbnailType {
    LCD = 1,
    THM = 2
  }

  export class HighlightAlbum {
    constructor(album: Album) {}
  }

  export enum CloudEnhancementTaskStage {
    TASK_STAGE_EXCEPTION = -1,
    TASK_STAGE_PREPARING,
    TASK_STAGE_UPLOADING,
    TASK_STAGE_EXECUTING,
    TASK_STAGE_DOWNLOADING,
    TASK_STAGE_FAILED,
    TASK_STAGE_COMPLETED
  }

  export interface CloudEnhancementTaskState {
    readonly taskStage: CloudEnhancementTaskStage;
    readonly transferredFileSize?: number;
    readonly totalFileSize?: number;
    readonly expectedDuration?: number;
    readonly statusCode?: number;
  }

  export class CloudEnhancement {
  }

  export enum CloudEnhancementState {
    UNAVAILABLE = 0,
    AVAILABLE,
    EXECUTING,
    COMPLETED
  }
}
