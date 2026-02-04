using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WT.Application.Extensions;

namespace API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class MetadataController : Controller
    {

        [HttpGet("countries")]
        [AllowAnonymous] // Usually public so registration can see it
        public IActionResult GetCountries()
        {
            var countries = StringHelpers.GetCountryCodes();
            return Ok(countries);
        }

        [HttpGet("trail-difficulties")]
        [AllowAnonymous] // Usually public so registration can see it
        public IActionResult GetTrailDifficulties()
        {
            var difficulties = StringHelpers.GetTrailDifficulties();
            return Ok(difficulties);
        }

        [HttpGet("surface-types")]
        [AllowAnonymous] // Usually public so registration can see it
        public IActionResult GetSurfaceTypes()
        {
            var surfaceTypes = StringHelpers.GetTrailSurfaceType();
            return Ok(surfaceTypes);
        }
    }
}
