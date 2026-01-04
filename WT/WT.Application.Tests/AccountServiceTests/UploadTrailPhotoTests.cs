using Moq;
using Moq.Protected;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using WT.Application.DTO.Request.Trail;
using WT.Application.DTO.Response;
using WT.Application.Services;
using Blazored.LocalStorage;
using Microsoft.Extensions.Configuration;
using System.Reflection;

namespace WT.Application.Tests.AccountServiceTests
{
    public class UploadTrailPhotoTests
    {
        [Fact]
        public async Task UploadTrailPhotoAsync_RecreatesMultipart_PerformsRequestAndParsesResponse()
        {
            // Arrange
            var handlerMock = new Mock<HttpMessageHandler>();
            var responseObj = new APIResponseUploadPhoto { Success = true, Message = "ok", PhotoUrl = "https://cdn.test/photo.jpg" };
            var httpResponse = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(responseObj))
            };

            handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(httpResponse);

            var httpClient = new HttpClient(handlerMock.Object)
            {
                BaseAddress = new Uri("https://localhost")
            };

            var inMemorySettings = new Dictionary<string, string> {
 { "ApplicationSettings:LocalStorageKey", "testkey" }
 };
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(inMemorySettings).Build();

            var localStorageMock = new Mock<ILocalStorageService>();
            var auth = new { JWtToken = "token" };
            localStorageMock.Setup(x => x.GetItemAsStringAsync(It.IsAny<string>())).ReturnsAsync(JsonSerializer.Serialize(auth));

            var svc = new AccountService(httpClient, configuration, localStorageMock.Object);

            // Create a minimal IFormFile via MemoryStream
            var ms = new MemoryStream(new byte[] { 0xFF, 0xD8, 0xFF, 0x00 }); // JPEG header
            var formFile = new FormFile(ms, 0, ms.Length, "TrailPhoto", "photo.jpg") { Headers = new HeaderDictionary(), ContentType = "image/jpeg" };

            var dto = new AddTrailPhotoRequestDTO { TrailId = Guid.NewGuid(), TrailPhoto = formFile, ContentType = "image/jpeg" };

            // Act
            var result = await svc.UploadTrailPhotoAsync(dto);

            // Assert
            Assert.NotNull(result);
            Assert.True(result.Success);
            Assert.Equal(responseObj.PhotoUrl, result.PhotoUrl);
        }
    }
}
