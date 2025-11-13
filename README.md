# Fun Quizz - Backend

NestJS (v11) API phục vụ cho nền tảng Fun Quizz: quản lý người dùng, xác thực JWT và các dịch vụ nền tảng như PostgreSQL, Redis. Tất cả được viết bằng TypeScript, sẵn sàng mở rộng thêm module quiz trong các sprint tiếp theo.

## Giới thiệu

- NestJS + TypeORM kết nối PostgreSQL, bật `synchronize` để tự tạo schema trong môi trường phát triển.
- Redis được đóng gói qua `RedisModule` dùng `ioredis`, sẵn cho cache hoặc hàng đợi sự kiện.
- Module `auth` chịu trách nhiệm đăng ký/đăng nhập, cấp JWT theo chuẩn Bearer.
- Module `users` cung cấp CRUD, bảo vệ bằng `JwtAuthGuard`.
- Lớp `ResponseInterceptor` chuẩn hóa mọi phản hồi về một định dạng thống nhất (`statusCode`, `message`, `timestamp`, `data`).

## Công nghệ chính

- Node.js 20+, NestJS 11, TypeScript 5.7.
- TypeORM + PostgreSQL cho tầng dữ liệu.
- Passport + @nestjs/jwt cho bảo mật phiên.
- Redis 7 (thông qua `ioredis`) cho cache hoặc rate-limit.
- Swagger/OpenAPI tự động bật ở `/api` khi `NODE_ENV=development`.

## Yêu cầu hệ thống

- Node.js >= 20 và npm >= 10.
- Docker (tùy chọn) nếu muốn chạy PostgreSQL/Redis qua `docker compose`.
- PostgreSQL và Redis cục bộ nếu không dùng Docker.

## Thiết lập môi trường

1. Cài đặt phụ thuộc:

   ```bash
   npm install
   ```

2. Tạo file `.env` ở thư mục gốc (tham khảo ví dụ bên dưới) hoặc inject qua biến môi trường của hệ điều hành:

   ```dotenv
   NODE_ENV=development
   PORT=3000

   DB_HOST=localhost
   DB_PORT=5432
   DB_USER=fun-quizz
   DB_PASSWORD=fun-quizz
   DB_NAME=fun-quizz

   REDIS_HOST=localhost
   REDIS_PORT=6379
   REDIS_DB=0

   JWT_SECRET=super-secret-change-me
   JWT_EXPIRES_IN=3600
   ```

## Sử dụng Docker

Dự án cung cấp `docker-compose.yml` để dựng nhanh PostgreSQL và Redis:

```bash
docker compose up -d postgres redis
```

Các service sẽ lắng nghe ở `5432` và `6379` tương ứng, dữ liệu được lưu trong volume `postgres_data`/`redis_data`.

## Chạy ứng dụng

| Lệnh              | Mô tả                                   |
| ----------------- | ---------------------------------------- |
| `npm run start`   | chạy chế độ production (biên dịch sẵn).  |
| `npm run start:dev` | hot-reload phục vụ phát triển.        |
| `npm run start:prod` | chạy kết quả build trong `dist`.     |

Sau khi khởi chạy, API mặc định ở `http://localhost:3000`. Khi đang ở `development`, truy cập `http://localhost:3000/api` để xem tài liệu Swagger và thử nhanh các endpoint `auth`, `users`.

## Cấu trúc thư mục

```
src
├── common
│   ├── interceptors/response.interceptor.ts  # Chuẩn hóa response
│   └── redis                                 # Định nghĩa Redis client dạng Global module
├── modules
│   ├── auth                                  # Đăng nhập, đăng ký, JWT guard/strategy
│   └── users                                 # DTO, entity, mapper, service & controller
├── app.module.ts                             # Khởi tạo ConfigModule, TypeORM, Redis
└── main.ts                                   # Bootstrap app, bật Helmet, CORS, Swagger
```

## Bảo mật & chuẩn API

- Tất cả route `users/*` đều required Bearer token hợp lệ (JWT do `auth/login` cấp).
- Mật khẩu người dùng được băm bằng `bcryptjs` và ẩn khỏi phản hồi thông qua `ClassSerializerInterceptor`.
- Mọi response đều có dạng:

  ```json
  {
    "statusCode": 200,
    "message": "Success",
    "timestamp": "2025-01-01T00:00:00.000Z",
    "data": { "...payload" }
  }
  ```

Điều này giúp frontend chỉ cần xử lý một contract duy nhất.

## Kiểm thử & chất lượng mã

| Lệnh              | Công dụng                                       |
| ----------------- | ------------------------------------------------ |
| `npm run test`    | unit test với Jest.                             |
| `npm run test:e2e`| end-to-end test (cấu hình tại `test/jest-e2e.json`). |
| `npm run test:cov`| báo cáo coverage.                               |
| `npm run lint`    | eslint + prettier để đảm bảo coding-style.      |
| `npm run format`  | format toàn bộ `src` và `test`.                 |

Khuyến nghị chạy `npm run lint && npm run test` trước khi mở PR.

## Ghi chú triển khai

- `TypeOrmModule` đang bật `synchronize: true`; hãy tắt và dùng migration khi lên môi trường production.
- Thiết lập biến `JWT_SECRET` đủ mạnh và `JWT_EXPIRES_IN` phù hợp (giây).
- Dùng reverse proxy (Nginx, Cloudflare, ...) để bật HTTPS và rate-limit khi triển khai thực tế.

## Định hướng mở rộng

- Thêm module quiz (câu hỏi, phòng chơi, bảng xếp hạng) dựa trên cấu trúc module hiện hữu.
- Áp dụng Redis cho cache token bị thu hồi hoặc session realtime.
- Thiết lập CI (GitHub Actions) chạy lint/test tự động trên mỗi PR.
