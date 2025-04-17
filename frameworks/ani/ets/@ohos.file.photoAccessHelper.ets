/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
import { CustomColors } from '@ohos.arkui.theme';

class SizeImpl implements image.Size {
  height: int = 0;
  width: int = 0;
}

type RejectString = (e: BusinessError<string>) => void;

function businessError<T = void>(c: number, d?: string): BusinessError<T> {
  let err: BusinessError<T> = new BusinessError<T>();
  err.code = c;
  err.message = d ? d : "";
  return err;
}

function isNullish(d: NullishType): boolean {
  return (d === null || d === undefined) ? true : false;
}

class MediaLibraryAniError extends BusinessError {
  constructor(code: number, message: string) {
    super();
    this.code = code;
    this.message = message;
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

  type MediaAssetDataType = image.ImageSource | ArrayBuffer | MovingPhoto | boolean;
  type QuickImageDataType = image.Picture;

  export class MediaAssetManager {
    static onMediaAssetDataPrepared(data: MediaAssetDataType, map?: Map<string, string>,
      dataHandler: MediaAssetDataHandler<MediaAssetDataType>): void {
      if (dataHandler !== undefined && dataHandler !== null) {
        dataHandler.onDataPrepared(data, map);
      }
    }

    static onQuickImageDataPrepared(data: QuickImageDataType, imageSource: image.ImageSource,
      map: Map<string, string>, dataHandler: QuickImageDataHandler<QuickImageDataType>): void {
      if (dataHandler !== undefined && dataHandler !== null) {
        dataHandler.onDataPrepared(data, imageSource, map);
      }
    }

    static onMediaAssetProgress(progress: number, progressHandler: MediaAssetProgressHandler): void {
      if (progressHandler !== undefined && progressHandler !== null) {
        progressHandler.onProgress(progress);
      }
    }

    native static requestImageInner(context: Context, asset: PhotoAsset, requestOptions: RequestOptions,
      dataHandler: MediaAssetDataHandler<image.ImageSource>): string;
    native static quickRequestImageInner(context: Context, asset: PhotoAsset, requestOptions: RequestOptions,
      dataHandler: QuickImageDataHandler<image.Picture>): string;
    native static requestImageDataInner(context: Context, asset: PhotoAsset, requestOptions: RequestOptions,
      dataHandler: MediaAssetDataHandler<ArrayBuffer>): string;
    native static requestMovingPhotoInner(context: Context, asset: PhotoAsset, requestOptions: RequestOptions,
      dataHandler: MediaAssetDataHandler<MovingPhoto>): string;
    native static cancelRequestInner(context: Context, requestId: string): void;
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

    native get(member: string): MemberType;

    native set(member: string, value: string): void;

    commitModify(callback: AsyncCallback<void>): void {
      let cb = (): MediaLibraryAniError | undefined => {
        try {
          this.commitModifySync();
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
          callback(businessError(err.code, err.message), undefined);
        }
      });
    }

    commitModify(): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: (e: BusinessError<void>) => void): void => {
        let cb = (): MediaLibraryAniError | undefined => {
          try {
            this.commitModifySync();
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
            reject(businessError(err.code, err.message));
          }
        });
      });
    }

    open(mode: string, callback: AsyncCallback<number | undefined>): void {
      let cb = (): MediaLibraryAniError | number => {
        try {
          return this.openSync(mode);
        } catch(e) {
          return e as MediaLibraryAniError;
        }
      };
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof MediaLibraryAniError) {
          let err = ret as MediaLibraryAniError;
          callback(businessError(err.code, err.message), undefined);
        } else {
          if (isNullish(ret)) {
            callback(businessError(-1, "Operation failed"), undefined);
          } else {
            callback(businessError(0), ret as number);
          }
        }
      });
    }

    open(mode: string): Promise<number> {
      return new Promise<number>((resolve: (v: number) => void, reject: RejectString) => {
        let cb = (): number | MediaLibraryAniError => {
          try {
            return this.openSync(mode);
          } catch(e) {
            return e as MediaLibraryAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret instanceof MediaLibraryAniError) {
            let err = ret as MediaLibraryAniError;
            reject(businessError<string>(err.code, err.message));
          } else {
            if (isNullish(ret)) {
              reject(businessError<string>(-1, "Operation failed"));
            } else {
              resolve(ret as number);
            }
          }
        });
      });
    }

    close(fd: number, callback: AsyncCallback<void>): void {
      let cb = (): MediaLibraryAniError | undefined => {
        try {
          this.closeSync(fd);
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
          callback(businessError(err.code, err.message), undefined);
        }
      });
    }

    close(fd: number): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: (e: BusinessError<void>) => void): void => {
        let cb = (): MediaLibraryAniError | undefined => {
          try {
            this.closeSync(fd);
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
            reject(businessError(err.code, err.message));
          }
        });
      });
    }

    getThumbnail(callback: AsyncCallback<image.PixelMap | undefined>): void {
      let cb = (): MediaLibraryAniError | image.PixelMap | undefined => {
        try {
          return this.getThumbnailSync();
        } catch(e) {
          return e as MediaLibraryAniError;
        }
      };
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof MediaLibraryAniError) {
          let err = ret as MediaLibraryAniError;
          callback(businessError(err.code, err.message), undefined);
        } else {
          if (isNullish(ret)) {
            callback(businessError(-1, "Operation failed"), undefined);
          } else {
            callback(businessError(0), ret as image.PixelMap | undefined);
          }
        }
      });
    }

    getThumbnail(size: image.Size, callback: AsyncCallback<image.PixelMap | undefined>): void {
      let cb = (): MediaLibraryAniError | image.PixelMap | undefined => {
        try {
          return this.getThumbnailSync(size);
        } catch(e) {
          return e as MediaLibraryAniError;
        }
      };
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof MediaLibraryAniError) {
          let err = ret as MediaLibraryAniError;
          callback(businessError(err.code, err.message), undefined);
        } else {
          if (isNullish(ret)) {
            callback(businessError(-1, "Operation failed"), undefined);
          } else {
            callback(businessError(0), ret as image.PixelMap | undefined);
          }
        }
      });
    }

    getThumbnail(size?: image.Size): Promise<image.PixelMap> {
      return new Promise<image.PixelMap>((resolve: (v: image.PixelMap) => void, reject: RejectString) => {
        let cb = (): image.PixelMap | MediaLibraryAniError => {
          try {
            return this.getThumbnailSync(size);
          } catch(e) {
            return e as MediaLibraryAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret instanceof MediaLibraryAniError) {
            let err = ret as MediaLibraryAniError;
            reject(businessError<string>(err.code, err.message));
          } else {
            if (isNullish(ret)) {
              reject(businessError<string>(-1, "Operation failed"));
            } else {
              resolve(ret as image.PixelMap);
            }
          }
        });
      });
    }

    setFavorite(favoriteState: boolean, callback: AsyncCallback<void>): void {
      let cb = (): MediaLibraryAniError | undefined => {
        try {
          this.setFavoriteSync(favoriteState);
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
          callback(businessError(err.code, err.message), undefined);
        }
      });
    }

    setFavorite(favoriteState: boolean): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: (e: BusinessError<void>) => void): void => {
        let cb = (): MediaLibraryAniError | undefined => {
          try {
            this.setFavoriteSync(favoriteState);
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
            reject(businessError(err.code, err.message));
          }
        });
      });
    }

    setHidden(hiddenState: boolean, callback: AsyncCallback<void>): void {
      let cb = (): MediaLibraryAniError | undefined => {
        try {
          this.setHiddenSync(hiddenState);
          return undefined;
        } catch(e) {
          return e as MediaLibraryAniError;
        }
      };
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (isNullish(ret)) {
          callback(businessError(0), undefined);
        } else {
          let err = ret as MediaLibraryAniError;
          callback(businessError(err.code, err.message), undefined);
        }
      });
    }

    setHidden(hiddenState: boolean): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: (e: BusinessError<void>) => void): void => {
        let cb = (): MediaLibraryAniError | undefined => {
          try {
            this.setHiddenSync(hiddenState);
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
            reject(businessError(err.code, err.message));
          }
        });
      });
    }

    setUserComment(userComment: string, callback: AsyncCallback<void>): void {
      let cb = (): MediaLibraryAniError | undefined => {
        try {
          this.setUserCommentSync(userComment);
          return undefined;
        } catch(e) {
          return e as MediaLibraryAniError;
        }
      };
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (isNullish(ret)) {
          callback(businessError(0), undefined);
        } else {
          let err = ret as MediaLibraryAniError;
          callback(businessError(err.code, err.message), undefined);
        }
      });
    }

    setUserComment(userComment: string): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: (e: BusinessError<void>) => void): void => {
        let cb = (): MediaLibraryAniError | undefined => {
          try {
            this.setUserCommentSync(userComment);
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
            reject(businessError(err.code, err.message));
          }
        });
      });
    }

    getAnalysisData(analysisType: AnalysisType): Promise<string> {
      return new Promise<string>((resolve: (v: string) => void, reject: RejectString) => {
        let cb = (): string | MediaLibraryAniError => {
          try {
            return this.getAnalysisDataSync(analysisType);
          } catch(e) {
            return e as MediaLibraryAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret instanceof MediaLibraryAniError) {
            let err = ret as MediaLibraryAniError;
            reject(businessError<string>(err.code, err.message));
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

    native commitModifySync(): void;
    native openSync(mode: string): number;
    native closeSync(fd: number): void;
    native getThumbnailSync(size?: image.Size): image.PixelMap;
    native setFavoriteSync(favoriteState: boolean): void;
    native setHiddenSync(hiddenState: boolean): void;
    native setUserCommentSync(userComment: string): void;
    native getAnalysisDataSync(analysisType: AnalysisType): string;
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
    getObjectByPosition(index: number, callback: AsyncCallback<T | undefined>): void;
    getObjectByPosition(index: number): Promise<T>;
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
    isAfterLast(): boolean {
      return false;
    }
    getFirstObject(callback: AsyncCallback<T | undefined, void>): void {
      let cb = (): T | MediaLibraryAniError => {
        try {
          return this.getFirstObjectSync();
        } catch(e) {
          return e as MediaLibraryAniError;
        }
      };
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof MediaLibraryAniError) {
          let err = ret as MediaLibraryAniError;
          callback(businessError(err.code, err.message), undefined);
        } else {
          if (isNullish(ret)) {
            callback(businessError(-1), undefined);
          } else {
            callback(businessError(0), ret as T);
          }
        }
      });
    }

    getFirstObject(): Promise<T> {
      return new Promise<T>((resolve: (v: T) => void, reject: RejectString) => {
        let cb = (): T | MediaLibraryAniError => {
          try {
            return this.getFirstObjectSync();
          } catch(e) {
            return e as MediaLibraryAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret instanceof MediaLibraryAniError) {
            let err = ret as MediaLibraryAniError;
            reject(businessError<string>(err.code, err.message));
          } else {
            if (isNullish(ret)) {
              reject(businessError<string>(-1, "Operation failed"));
            } else {
              resolve(ret as T);
            }
          }
        });
      });
    }

    getNextObject(callback: AsyncCallback<T | undefined, void>): void {
      let cb = (): T | MediaLibraryAniError => {
        try {
          return this.getNextObjectSync();
        } catch(e) {
          return e as MediaLibraryAniError;
        }
      };
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof MediaLibraryAniError) {
          let err = ret as MediaLibraryAniError;
          callback(businessError(err.code, err.message), undefined);
        } else {
          if (isNullish(ret)) {
            callback(businessError(-1), undefined);
          } else {
            callback(businessError(0), ret as T);
          }
        }
      });
    }

    getNextObject(): Promise<T> {
      return new Promise<T>((resolve: (v: T) => void, reject: RejectString) => {
        let cb = (): T | MediaLibraryAniError => {
          try {
            return this.getNextObjectSync();
          } catch(e) {
            return e as MediaLibraryAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret instanceof MediaLibraryAniError) {
            let err = ret as MediaLibraryAniError;
            reject(businessError<string>(err.code, err.message));
          } else {
            if (isNullish(ret)) {
              reject(businessError<string>(-1, "Operation failed"));
            } else {
              resolve(ret as T);
            }
          }
        });
      });
    }

    getObjectByPosition(index: number, callback: AsyncCallback<T | undefined>): void {
      let cb = (): MediaLibraryAniError | T => {
        try {
          return this.getObjectByPositionSync(index);
        } catch(e) {
          return e as MediaLibraryAniError;
        }
      };
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof MediaLibraryAniError) {
          let err = ret as MediaLibraryAniError;
          callback(businessError(err.code, err.message), undefined);
        } else {
          if (isNullish(ret)) {
            callback(businessError(-1, "Operation failed"), undefined);
          } else {
            callback(businessError(0), ret as T);
          }
        }
      });
    }

    getObjectByPosition(index: number): Promise<T> {
      return new Promise<T>((resolve: (v: T) => void, reject: RejectString) => {
        let cb = (): T | MediaLibraryAniError => {
          try {
            return this.getObjectByPositionSync(index);
          } catch(e) {
            return e as MediaLibraryAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret instanceof MediaLibraryAniError) {
            let err = ret as MediaLibraryAniError;
            reject(businessError<string>(err.code, err.message));
          } else {
            if (isNullish(ret)) {
              reject(businessError<string>(-1, "Operation failed"));
            } else {
              resolve(ret as T);
            }
          }
        });
      });
    }

    getAllObjects(callback: AsyncCallback<Array<T> | undefined, void>): void {
      let blockQueue: BlockingQueue<Array<T> | MediaLibraryAniError> =
        new ArrayBlockingQueue<Array<T> | MediaLibraryAniError>(2);
      let cb = (): Array<T> | MediaLibraryAniError => {
        let result: Array<T> | MediaLibraryAniError;
        try {
          result = this.getAllObjectsSync();
        } catch(e) {
          result = e as MediaLibraryAniError;
        }
        blockQueue.push(result);
        return result;
      };
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof MediaLibraryAniError) {
          let err = ret as MediaLibraryAniError;
          callback(businessError(err.code, err.message), undefined);
        } else {
          if (isNullish(ret)) {
            callback(businessError(-1), undefined);
          } else {
            callback(businessError(0), ret as Array<T>);
          }
        }
      });
      blockQueue.pop();
    }

    getAllObjects(): Promise<Array<T>> {
      return new Promise<Array<T>>((resolve: (v: Array<T>) => void, reject: RejectString) => {
        let blockQueue: BlockingQueue<Array<T> | MediaLibraryAniError> =
          new ArrayBlockingQueue<Array<T> | MediaLibraryAniError>(2);
        let cb = (): Array<T> | MediaLibraryAniError => {
        let result: Array<T> | MediaLibraryAniError;
          try {
            result = this.getAllObjectsSync();
          } catch(e) {
            result = e as MediaLibraryAniError;
          }
          blockQueue.push(result);
          return result;
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret instanceof MediaLibraryAniError) {
            let err = ret as MediaLibraryAniError;
            reject(businessError<string>(err.code, err.message));
          } else {
            if (isNullish(ret)) {
              reject(businessError<string>(-1, "Operation failed"));
            } else {
              resolve(ret as Array<T>);
            }
          }
        });
        blockQueue.pop();
      });
    }

    native close(): void;

    native getFirstObjectSync(): T;
    native getNextObjectSync(): T;
    native getAllObjectsSync(): Array<T>;
    native getObjectByPositionSync(index: number): T;
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
          callback(businessError(err.code, err.message), undefined);
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
            reject(businessError<string>(err.code, err.message));
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
          callback(businessError(err.code, err.message), undefined);
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
            reject(businessError(err.code, err.message));
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
          callback(businessError(err.code, err.message), undefined);
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
            reject(businessError(err.code, err.message));
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
          callback(businessError(err.code, err.message), undefined);
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
            reject(businessError(err.code, err.message));
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
          callback(businessError(err.code, err.message), undefined);
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
            reject(businessError(err.code, err.message));
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
          callback(businessError(err.code, err.message), undefined);
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
            reject(businessError(err.code, err.message));
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
          callback(businessError(err.code, err.message), undefined);
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
            reject(businessError(err.code, err.message));
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
            reject(businessError<string>(err.code, err.message));
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
    getAlbums(type: AlbumType, subtype: AlbumSubtype, options: FetchOptions,
       callback: AsyncCallback<FetchResult<Album> | undefined>): void;
    getAlbums(type: AlbumType, subtype: AlbumSubtype, callback: AsyncCallback<FetchResult<Album> | undefined>): void;
    getAlbums(type: AlbumType, subtype: AlbumSubtype, options?: FetchOptions): Promise<FetchResult<Album>>;
    createAssetsForApp(bundleName: string, appName: string, appId: string,
      photoCreationConfigs: Array<PhotoCreationConfig>): Promise<Array<string>>;
    createAssetsForAppWithMode(bundleName: string, appName: string, appId: string, tokenId: number,
      authorizationMode: AuthorizationMode, photoCreationConfigs: Array<PhotoCreationConfig>): Promise<Array<string>>;
    release(callback: AsyncCallback<void>): void;
    release(): Promise<void>;
    saveFormInfo(info: FormInfo, callback: AsyncCallback<void>): void;
    saveFormInfo(info: FormInfo): Promise<void>;
    applyChanges(mediaChangeRequest: MediaChangeRequest): Promise<void>;
    getIndexConstructProgress(): Promise<string>;
    grantPhotoUriPermission(appid: string, uri: string, photoPermissionType: PhotoPermissionType,
      hideSensitiveType: HideSensitiveType): Promise<number>;
  }

  interface AppInfo {
    bundleName: string;
    appName: string;
    appId: string;
    tokenId?: number;
  }

  interface GrantPhotoUriPermissionParam {
    appid: string;
    uri: string;
  }

  class PhotoAccessHelperHandle implements PhotoAccessHelper {
    private nativeHandle: long = 0;

    constructor(nativePtr: long) {
      if (this.nativeHandle == 0) {
        this.nativeHandle = nativePtr;
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
          callback(businessError(err.code, err.message), undefined);
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
        let blockQueue: BlockingQueue<FetchResult<PhotoAsset>> = new ArrayBlockingQueue<FetchResult<PhotoAsset>>(2);
        let cb = (): FetchResult<PhotoAsset> => {
          let result = this.getAssetsInner(options)
          blockQueue.push(result)
          return result
        };

        taskpool.execute(cb).then((buffer: NullishType): void => {
          if (isNullish(buffer)) {
            reject(businessError<string>(-1, "Operation failed"));
          } else {
            resolve(buffer as FetchResult<PhotoAsset>);
          }
        });

        blockQueue.pop();
      });
    }

    getBurstAssets(burstKey: string, options: FetchOptions): Promise<FetchResult<PhotoAsset>> {
      return new Promise<FetchResult<PhotoAsset>>((resolve: (v: FetchResult<PhotoAsset>) => void,
        reject: RejectString) => {
        let cb = (): FetchResult<PhotoAsset> | MediaLibraryAniError => {
          try {
            return this.getBurstAssetsInner(burstKey, options);
          } catch(e) {
            return e as MediaLibraryAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret instanceof MediaLibraryAniError) {
            let err = ret as MediaLibraryAniError;
            reject(businessError<string>(err.code, err.message));
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

    createAsset(displayName: string, callback: AsyncCallback<PhotoAsset | undefined>): void {
      let cb = (): MediaLibraryAniError | PhotoAsset => {
        try {
          return this.createAssetSystemInner(displayName);
        } catch(e) {
          return e as MediaLibraryAniError;
        }
      };
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof MediaLibraryAniError) {
          let err = ret as MediaLibraryAniError;
          callback(businessError(err.code, err.message), undefined);
        } else {
          if (isNullish(ret)) {
            callback(businessError(-1, "Operation failed"), undefined);
          } else {
            callback(businessError(0), ret as PhotoAsset);
          }
        }
      });
    }

    createAsset(displayName: string): Promise<PhotoAsset> {
      return new Promise<PhotoAsset>((resolve: (v: PhotoAsset) => void, reject: RejectString) => {
        let cb = (): PhotoAsset | MediaLibraryAniError => {
          try {
            return this.createAssetSystemInner(displayName);
          } catch(e) {
            return e as MediaLibraryAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret instanceof MediaLibraryAniError) {
            let err = ret as MediaLibraryAniError;
            reject(businessError<string>(err.code, err.message));
          } else {
            if (isNullish(ret)) {
              reject(businessError<string>(-1, "Operation failed"));
            } else {
              resolve(ret as PhotoAsset);
            }
          }
        });
      });
    }

    createAsset(displayName: string, options: PhotoCreateOptions): Promise<PhotoAsset> {
      return new Promise<PhotoAsset>((resolve: (v: PhotoAsset) => void, reject: RejectString) => {
        let cb = (): PhotoAsset | MediaLibraryAniError => {
          try {
            return this.createAssetSystemInner(displayName, options);
          } catch(e) {
            return e as MediaLibraryAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret instanceof MediaLibraryAniError) {
            let err = ret as MediaLibraryAniError;
            reject(businessError<string>(err.code, err.message));
          } else {
            if (isNullish(ret)) {
              reject(businessError<string>(-1, "Operation failed"));
            } else {
              resolve(ret as PhotoAsset);
            }
          }
        });
      });
    }

    createAsset(displayName: string, options: PhotoCreateOptions,
      callback: AsyncCallback<PhotoAsset | undefined>): void {
      let cb = (): MediaLibraryAniError | PhotoAsset => {
        try {
          return this.createAssetSystemInner(displayName, options);
        } catch(e) {
          return e as MediaLibraryAniError;
        }
      };
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof MediaLibraryAniError) {
          let err = ret as MediaLibraryAniError;
          callback(businessError(err.code, err.message), undefined);
        } else {
          if (isNullish(ret)) {
            callback(businessError(-1, "Operation failed"), undefined);
          } else {
            callback(businessError(0), ret as PhotoAsset);
          }
        }
      });
    }

    createAsset(photoType: PhotoType, extension: string, options: CreateOptions,
      callback: AsyncCallback<string | undefined>): void {
      let cb = (): MediaLibraryAniError | string => {
        try {
          return this.createAssetComponentInner(photoType, extension, options);
        } catch(e) {
          return e as MediaLibraryAniError;
        }
      };
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof MediaLibraryAniError) {
          let err = ret as MediaLibraryAniError;
          callback(businessError(err.code, err.message), undefined);
        } else {
          if (isNullish(ret)) {
            callback(businessError(-1, "Operation failed"), undefined);
          } else {
            callback(businessError(0), ret as string);
          }
        }
      });
    }

    createAsset(photoType: PhotoType, extension: string, callback: AsyncCallback<string | undefined>): void {
      let cb = (): MediaLibraryAniError | string => {
        try {
          return this.createAssetComponentInner(photoType, extension);
        } catch(e) {
          return e as MediaLibraryAniError;
        }
      };
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof MediaLibraryAniError) {
          let err = ret as MediaLibraryAniError;
          callback(businessError(err.code, err.message), undefined);
        } else {
          if (isNullish(ret)) {
            callback(businessError(-1, "Operation failed"), undefined);
          } else {
            callback(businessError(0), ret as string);
          }
        }
      });
    }

    createAsset(photoType: PhotoType, extension: string, options?: CreateOptions): Promise<string> {
      return new Promise<string>((resolve: (v: string) => void, reject: RejectString) => {
        let cb = (): string | MediaLibraryAniError => {
          try {
            return this.createAssetComponentInner(photoType, extension, options);
          } catch(e) {
            return e as MediaLibraryAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret instanceof MediaLibraryAniError) {
            let err = ret as MediaLibraryAniError;
            reject(businessError<string>(err.code, err.message));
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

    getAlbums(type: AlbumType, subtype: AlbumSubtype, options: FetchOptions,
      callback: AsyncCallback<FetchResult<Album> | undefined>): void {
      let cb = (): MediaLibraryAniError | FetchResult<Album> => {
        try {
          return this.getAlbumsInner(type, subtype, options);
        } catch(e) {
          return e as MediaLibraryAniError;
        }
      };
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof MediaLibraryAniError) {
          let err = ret as MediaLibraryAniError;
          callback(businessError(err.code, err.message), undefined);
        } else {
          if (isNullish(ret)) {
            callback(businessError(-1, "Operation failed"), undefined);
          } else {
            callback(businessError(0), ret as FetchResult<Album>);
          }
        }
      });
    }

    getAlbums(type: AlbumType, subtype: AlbumSubtype, callback: AsyncCallback<FetchResult<Album> | undefined>): void {
      let cb = (): MediaLibraryAniError | FetchResult<Album> => {
        try {
          return this.getAlbumsInner(type, subtype);
        } catch(e) {
          return e as MediaLibraryAniError;
        }
      };
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof MediaLibraryAniError) {
          let err = ret as MediaLibraryAniError;
          callback(businessError(err.code, err.message), undefined);
        } else {
          if (isNullish(ret)) {
            callback(businessError(-1, "Operation failed"), undefined);
          } else {
            callback(businessError(0), ret as FetchResult<Album>);
          }
        }
      });
    }

    getAlbums(type: AlbumType, subtype: AlbumSubtype, options?: FetchOptions): Promise<FetchResult<Album>> {
      return new Promise<FetchResult<Album>>((resolve: (v: FetchResult<Album>) => void,
        reject: RejectString) => {
          let cb = (): FetchResult<Album> | MediaLibraryAniError => {
            try {
              return this.getAlbumsInner(type, subtype, options);
            } catch(e) {
              return e as MediaLibraryAniError;
            }
          };
          taskpool.execute(cb).then((ret: NullishType): void => {
            if (ret instanceof MediaLibraryAniError) {
              let err = ret as MediaLibraryAniError;
              reject(businessError<string>(err.code, err.message));
            } else {
              if (isNullish(ret)) {
                reject(businessError<string>(-1, "Operation failed"));
              } else {
                resolve(ret as FetchResult<Album>);
              }
            }
          });
      });
    }

    createAssetsForApp(bundleName: string, appName: string, appId: string,
      photoCreationConfigs: Array<PhotoCreationConfig>): Promise<Array<string>> {
      let appInfo: AppInfo = {
        bundleName: bundleName,
        appName: appName,
        appId: appId
      };
      return new Promise<Array<string>>((resolve: (v: Array<string>) => void, reject: RejectString) => {
        let cb = (): Array<string> | MediaLibraryAniError => {
          try {
            return this.createAssetsForAppInner(appInfo, photoCreationConfigs);
          } catch(e) {
            return e as MediaLibraryAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret instanceof MediaLibraryAniError) {
            let err = ret as MediaLibraryAniError;
            reject(businessError<string>(err.code, err.message));
          } else {
            if (isNullish(ret)) {
              reject(businessError<string>(-1, "Operation failed"));
            } else {
              resolve(ret as Array<string>);
            }
          }
        });
      });
    }

    createAssetsForAppWithMode(bundleName: string, appName: string, appId: string, tokenId: number,
      authorizationMode: AuthorizationMode, photoCreationConfigs: Array<PhotoCreationConfig>): Promise<Array<string>> {
      let appInfo: AppInfo = {
        bundleName: bundleName,
        appName: appName,
        appId: appId,
        tokenId: tokenId
      };
      return new Promise<Array<string>>((resolve: (v: Array<string>) => void, reject: RejectString) => {
        let cb = (): Array<string> | MediaLibraryAniError => {
          try {
            return this.createAssetsForAppWithModeInner(appInfo, authorizationMode, photoCreationConfigs);
          } catch(e) {
            return e as MediaLibraryAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret instanceof MediaLibraryAniError) {
            let err = ret as MediaLibraryAniError;
            reject(businessError<string>(err.code, err.message));
          } else {
            if (isNullish(ret)) {
              reject(businessError<string>(-1, "Operation failed"));
            } else {
              resolve(ret as Array<string>);
            }
          }
        });
      });
    }

    release(callback: AsyncCallback<void>): void {
      let cb = (): MediaLibraryAniError | undefined => {
        try {
          this.releaseInner();
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
        }
      });
    }

    release(): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: (e: BusinessError<void>) => void): void => {
        let cb = (): MediaLibraryAniError | undefined => {
          try {
            this.releaseInner();
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
            reject(businessError(err.code, err.message));
          }
        });
      });
    }

    saveFormInfo(info: FormInfo, callback: AsyncCallback<void>): void {
      let cb = (): MediaLibraryAniError | undefined => {
        try {
          this.saveFormInfoInner(info);
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
          callback(businessError(err.code, err.message), undefined);
        }
      });
    }

    saveFormInfo(info: FormInfo): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: (e: BusinessError<void>) => void): void => {
        let cb = (): MediaLibraryAniError | undefined => {
          try {
            this.saveFormInfoInner(info);
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
            reject(businessError(err.code, err.message));
          }
        });
      });
    }

    applyChanges(mediaChangeRequest: MediaChangeRequest): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: (e: BusinessError<void>) => void): void => {
        let cb = (): MediaLibraryAniError | undefined => {
          try {
            this.applyChangesInner(mediaChangeRequest);
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
            reject(businessError(err.code, err.message));
          }
        });
      });
    }

    getIndexConstructProgress(): Promise<string> {
      return new Promise<string>((resolve: (v: string) => void, reject: RejectString) => {
        let cb = (): string | MediaLibraryAniError => {
          try {
            return this.getIndexConstructProgressInner();
          } catch(e) {
            return e as MediaLibraryAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret instanceof MediaLibraryAniError) {
            let err = ret as MediaLibraryAniError;
            reject(businessError<string>(err.code, err.message));
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

    grantPhotoUriPermission(appid: string, uri: string, photoPermissionType: PhotoPermissionType,
      hideSensitiveType: HideSensitiveType): Promise<number> {
      let param: GrantPhotoUriPermissionParam = {
        appid: appid,
        uri: uri
      };
      return new Promise<number>((resolve: (v: number) => void, reject: RejectString) => {
        let cb = (): number | MediaLibraryAniError => {
          try {
            return this.grantPhotoUriPermissionInner(param, photoPermissionType, hideSensitiveType);
          } catch(e) {
            return e as MediaLibraryAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret instanceof MediaLibraryAniError) {
            let err = ret as MediaLibraryAniError;
            reject(businessError<string>(err.code, err.message));
          } else {
            if (isNullish(ret)) {
              reject(businessError<string>(-1, "Operation failed"));
            } else {
              resolve(ret as number);
            }
          }
        });
      });
    }

    native startCreateThumbnailTask(predicate: dataSharePredicates.DataSharePredicates): int;
    native stopThumbnailCreationTask(taskId: number): void;
    native registerChange(uri: string, forChildUris: boolean, callback: Callback<ChangeData>): void;
    native unRegisterChange(uri: string, callback?: Callback<ChangeData>): void;
    native getAssetsSync(options: FetchOptions): Array<PhotoAsset>;
    native getFileAssetsInfo(options: FetchOptions): Array<FileAssetInfo>;
    native getAssetsInner(options: FetchOptions): FetchResult<PhotoAsset>;
    native getBurstAssetsInner(burstKey: string, options: FetchOptions): FetchResult<PhotoAsset>;
    native createAssetSystemInner(displayName: string, options?: PhotoCreateOptions): PhotoAsset;
    native createAssetComponentInner(photoType: PhotoType, extension: string, options?: CreateOptions): string;
    native getAlbumsInner(type: AlbumType, subtype: AlbumSubtype, options?: FetchOptions): FetchResult<Album>;
    native createAssetsForAppInner(appInfo: AppInfo, photoCreationConfigs: Array<PhotoCreationConfig>): Array<string>;
    native createAssetsForAppWithModeInner(appInfo: AppInfo, authorizationMode: AuthorizationMode,
      photoCreationConfigs: Array<PhotoCreationConfig>): Array<string>;
    native releaseInner(): void;
    native saveFormInfoInner(info: FormInfo): void;
    native applyChangesInner(mediaChangeRequest: MediaChangeRequest): void;
    native getIndexConstructProgressInner(): string;
    native grantPhotoUriPermissionInner(param: GrantPhotoUriPermissionParam, photoPermissionType: PhotoPermissionType,
      hideSensitiveType: HideSensitiveType): number;
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
    uris: Array<string> = new Array<string>();
    extraUris: Array<string> = new Array<string>();
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
    themeColor: CustomColors | undefined;
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
    private _compatibleFormat: string;
    private _formatVersion: string;
    private _data: string;
    private nativeHandle: long = 0;

    private native nativeConstructor(compatibleFormat: string, formatVersion: string): void;
    private native compatibleFormatSetter(format: string): void;
    private native compatibleFormatGetter(): string;
    private native formatVersionSetter(version: string): void;
    private native formatVersionGetter(): string;
    private native dataSetter(data: string): void;
    private native dataGetter(): string;

    constructor(compatibleFormat: string, formatVersion: string) {
      this.nativeConstructor(compatibleFormat, formatVersion);
    }

    private create(context: long): void {
      if (this.nativeHandle == 0) {
        this.nativeHandle = context;
      }
    }

    set compatibleFormat(format: string) {
      this.compatibleFormatSetter(format);
    }

    get compatibleFormat(): string {
      return this.compatibleFormatGetter();
    }

    set formatVersion(version: string) {
      this.formatVersionSetter(version);
    }

    get formatVersion(): string {
      return this.formatVersionGetter();
    }

    set data(data: string) {
      this.dataSetter(data);
    }

    get data(): string {
      return this.dataGetter();
    }
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

  export type AssetType = PhotoAsset | string;

  export class MediaAssetChangeRequest implements MediaChangeRequest {
    private nativeHandle: long = 0;

    constructor(asset: PhotoAsset) {
      this.nativeConstructor(asset);
    }

    native static createImageAssetRequest(context: Context, fileUri: string): MediaAssetChangeRequest;

    native static createVideoAssetRequest(context: Context, fileUri: string): MediaAssetChangeRequest;

    static createAssetRequest(context: Context, displayName: string,
      options?: PhotoCreateOptions): MediaAssetChangeRequest {
      return MediaAssetChangeRequest.createAssetRequestByPhotoCreateOptions(context, displayName, options);
    }

    static createAssetRequest(context: Context, photoType: PhotoType, extension: string,
      options?: CreateOptions): MediaAssetChangeRequest {
      return MediaAssetChangeRequest.createAssetRequestByCreateOptions(context, photoType, extension, options);
    }

    static deleteAssets(context: Context, assets: Array<AssetType>): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: (e: BusinessError<void>) => void): void => {
        let cb = (): MediaLibraryAniError | undefined => {
          try {
            MediaAssetChangeRequest.deleteAssetsSync(context, assets);
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
            reject(businessError(err.code, err.message));
          }
        });
      });
    }

    native getAsset(): PhotoAsset;

    native setEditData(editData: MediaAssetEditData): void;

    native addResource(type: ResourceType, fileUri: string): void;

    native addResource(type: ResourceType, data: ArrayBuffer): void;

    native addResource(type: ResourceType, proxy: PhotoProxy): void;

    native setEffectMode(mode: MovingPhotoEffectMode): void;

    private create(nativePointer: long): void {
      if (this.nativeHandle == 0) {
        this.nativeHandle = nativePointer;
      }
    }

    private native nativeConstructor(asset: PhotoAsset): void;
    private native static createAssetRequestByPhotoCreateOptions(context: Context, displayName: string,
      options?: PhotoCreateOptions): MediaAssetChangeRequest;
    private native static createAssetRequestByCreateOptions(context: Context, photoType: PhotoType, extension: string,
      options?: CreateOptions): MediaAssetChangeRequest;
    private native static deleteAssetsSync(context: Context, assets: Array<AssetType>): void;
  }

  export class MediaAssetsChangeRequest implements MediaChangeRequest {
    private nativeHandle: long = 0;

    constructor(assets: Array<PhotoAsset>) {
      this.nativeConstructor(assets);
    }

    native setFavorite(favoriteState: boolean): void;

    native setHidden(hiddenState: boolean): void;

    setUserComment(userComment: string): void {}

    private create(context: long): void {
      if (this.nativeHandle == 0) {
        this.nativeHandle = context;
      }
    }

    native nativeConstructor(assets: Array<PhotoAsset>): void;
  }

  export class MediaAlbumChangeRequest implements MediaChangeRequest {
    private nativeHandle: long = 0;

    constructor(album: Album) {
      this.nativeConstructor(album);
    }

    static deleteAlbums(context: Context, albums: Array<Album>): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: RejectString) : void => {
        let cb = (): undefined | MediaLibraryAniError => {
          try {
            return MediaAlbumChangeRequest.deleteAlbumsSync(context, albums)
          } catch(e) {
            return e as MediaLibraryAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret instanceof MediaLibraryAniError) {
            let err = ret as MediaLibraryAniError;
            reject(businessError<string>(err.code, err.message));
          } else {
            if (isNullish(ret)) {
              reject(businessError<string>(-1, "Operation failed"));
            } else {
              resolve(undefined);
            }
          }
        });
      });
    }

    native setCoverUri(coverUri: string): void;

    native setAlbumName(name: string): void;

    native addAssets(assets: Array<PhotoAsset>): void;

    native moveAssets(assets: Array<PhotoAsset>, targetAlbum: Album): void;

    native recoverAssets(assets: Array<PhotoAsset>): void;

    native deleteAssets(assets: Array<PhotoAsset>): void;

    native setIsMe(): void;

    native setDisplayLevel(displayLevel: number): void;

    native dismissAssets(assets: Array<PhotoAsset>): void;

    native mergeAlbum(album: Album): void;

    native placeBefore(album: Album): void;

    private create(context: long): void {
      if (this.nativeHandle == 0) {
        this.nativeHandle = context;
      }
    }

    native nativeConstructor(album: Album): void;
    native static deleteAlbumsSync(context: Context, albums: Array<Album>): void;
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
      if (this.nativeMovingPhoto == 0) {
        this.nativeMovingPhoto = context;
      }
    }

    requestContent(imageFileUri: string, videoFileUri: string): Promise<void> {
      return new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: RejectString) => {
        let cb = (): PromiseLike<void> => { this.RequestContentByImageFileAndVideoFile(imageFileUri, videoFileUri) };
        taskpool.execute(cb).then((v: NullishType): void => {
          resolve(v as PromiseLike<void>);
        });
      });
    }

    requestContent(resourceType: ResourceType, fileUri: string): Promise<void> {
      return new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: RejectString) => {
        let cb = (): PromiseLike<void> => { this.RequestContentByResourceTypeAndFile(resourceType, fileUri) }
        taskpool.execute(cb).then((v: NullishType): void => {
          resolve(v as PromiseLike<void>);
        });
      });
    }

    requestContent(resourceType: ResourceType): Promise<ArrayBuffer> {
      return new Promise<ArrayBuffer>((resolve: (v: ArrayBuffer) => void, reject: RejectString) => {
        let cb = (): ArrayBuffer => { return this.RequestContentByResourceType(resourceType) };
        taskpool.execute(cb).then((buffer: NullishType): void => {
          if (isNullish(buffer)) {
            reject(businessError<string>(-1, "Operation failed"));
          } else {
            resolve(buffer as ArrayBuffer);
          }
        });
      });
    }

    native getUri(): string;
    native RequestContentByImageFileAndVideoFile(imageFileUri: string, videoFileUri: string): void;
    native RequestContentByResourceTypeAndFile(resourceType: ResourceType, fileUri: string): void;
    native RequestContentByResourceType(resourceType: ResourceType): ArrayBuffer;
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
    private nativePhotoAlbum: long = 0;

    constructor(album: Album) {
      let nativePtr: long = this.nativeConstructor(album);
      if (nativePtr != 0) {
        this.nativePhotoAlbum = nativePtr;
      }
    }

    getHighlightAlbumInfo(type: HighlightAlbumInfoType): Promise<string> {
      return new Promise<string>((resolve: (v: string) => void, reject: RejectString) => {
        let cb = (): string | MediaLibraryAniError => {
          try {
            return this.getHighlightAlbumInfoInner(type);
          } catch(e) {
            return e as MediaLibraryAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret instanceof MediaLibraryAniError) {
            let err = ret as MediaLibraryAniError;
            reject(businessError<string>(err.code, err.message));
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

    native nativeConstructor(album: Album): long;
    native getHighlightAlbumInfoInner(type: HighlightAlbumInfoType): string;
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

  class CloudEnhancementTaskStateHandle implements CloudEnhancementTaskState {
    readonly taskStage: CloudEnhancementTaskStage = CloudEnhancementTaskStage.TASK_STAGE_EXCEPTION;
    readonly transferredFileSize: number | undefined = undefined;
    readonly totalFileSize: number | undefined = undefined;
    readonly expectedDuration: number | undefined = undefined;
    readonly statusCode: number | undefined = undefined;
    private nativeHandle: long = 0;

    private constructor(nativePointer: long) {
      if (this.nativeHandle == 0) {
        this.nativeHandle = nativePointer;
        let undefinedValue: number = -1;
        this.transferredFileSize =
          this.getTransferredFileSize() == undefinedValue ? undefined : this.getTransferredFileSize();
        this.totalFileSize = this.getTotalFileSize() == undefinedValue ? undefined : this.getTotalFileSize();
        this.expectedDuration = this.getExpectedDuration() == undefinedValue ? undefined : this.getExpectedDuration();
        this.statusCode = this.getStatusCode() == undefinedValue ? undefined : this.getStatusCode();
      }
    }

    private native getTransferredFileSize(): number;
    private native getTotalFileSize(): number;
    private native getExpectedDuration(): number;
    private native getStatusCode(): number;
  }

  export class CloudEnhancement {
    private nativeHandle: long = 0;

    constructor(nativePointer: long) {
      if (this.nativeHandle == 0) {
        this.nativeHandle = nativePointer;
      }
    }

    native static getCloudEnhancementInstance(context: Context): CloudEnhancement;

    submitCloudEnhancementTasks(photoAssets: Array<PhotoAsset>, hasCloudWatermark: boolean): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: (e: BusinessError<void>) => void): void => {
        let cb = (): MediaLibraryAniError | undefined => {
          try {
            this.submitCloudEnhancementTasksSync(photoAssets, hasCloudWatermark);
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
            reject(businessError(err.code, err.message));
          }
        });
      });
    }

    prioritizeCloudEnhancementTask(photoAsset: PhotoAsset): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: (e: BusinessError<void>) => void): void => {
        let cb = (): MediaLibraryAniError | undefined => {
          try {
            this.prioritizeCloudEnhancementTaskSync(photoAsset);
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
            reject(businessError(err.code, err.message));
          }
        });
      });
    }

    cancelCloudEnhancementTasks(photoAssets: Array<PhotoAsset>): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: (e: BusinessError<void>) => void): void => {
        let cb = (): MediaLibraryAniError | undefined => {
          try {
            this.cancelCloudEnhancementTasksSync(photoAssets);
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
            reject(businessError(err.code, err.message));
          }
        });
      });
    }

    cancelAllCloudEnhancementTasks(): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: (e: BusinessError<void>) => void): void => {
        let cb = (): MediaLibraryAniError | undefined => {
          try {
            this.cancelAllCloudEnhancementTasksSync();
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
            reject(businessError(err.code, err.message));
          }
        });
      });
    }

    syncCloudEnhancementTaskStatus(): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: (e: BusinessError<void>) => void): void => {
        let cb = (): MediaLibraryAniError | undefined => {
          try {
            this.syncCloudEnhancementTaskStatusSync();
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
            reject(businessError(err.code, err.message));
          }
        });
      });
    }

    getCloudEnhancementPair(asset: PhotoAsset): Promise<PhotoAsset> {
      return new Promise<PhotoAsset>((resolve: (v: PhotoAsset) => void, reject: RejectString) => {
        let cb = (): PhotoAsset | MediaLibraryAniError => {
          try {
            return this.getCloudEnhancementPairSync(asset);
          } catch(e) {
            return e as MediaLibraryAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret instanceof MediaLibraryAniError) {
            let err = ret as MediaLibraryAniError;
            reject(businessError<string>(err.code, err.message));
          } else {
            if (isNullish(ret)) {
              reject(businessError<string>(-1, "Operation failed"));
            } else {
              resolve(ret as PhotoAsset);
            }
          }
        });
      });
    }

    private native submitCloudEnhancementTasksSync(photoAssets: Array<PhotoAsset>, hasCloudWatermark: boolean): void;
    private native prioritizeCloudEnhancementTaskSync(photoAsset: PhotoAsset): void;
    private native cancelCloudEnhancementTasksSync(photoAssets: Array<PhotoAsset>): void;
    private native cancelAllCloudEnhancementTasksSync(): void;
    private native queryCloudEnhancementTaskStateSync(photoAsset: PhotoAsset): CloudEnhancementTaskState;
    private native syncCloudEnhancementTaskStatusSync(): void;
    private native getCloudEnhancementPairSync(asset: PhotoAsset): PhotoAsset;
  }

  export enum CloudEnhancementState {
    UNAVAILABLE = 0,
    AVAILABLE,
    EXECUTING,
    COMPLETED
  }
}
